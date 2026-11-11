package geo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oschwald/maxminddb-golang"

	"restricted-access/internal/config"
)

const (
	maxArchiveBytes = 128 << 20
	maxUncompressed = 256 << 20
	maxTarEntries   = 32
	downloadTimeout = 5 * time.Minute
	userAgent       = "restricted-access/1.0"
)

var sha256Pattern = regexp.MustCompile(`(?i)^([a-f0-9]{64})\b`)

var defaultRedirectHosts = []string{
	"download.maxmind.com",
	"updates.maxmind.com",
	"mm-prod-geoip-databases.a2649acb697e2c09b632799562c076f2.r2.cloudflarestorage.com",
}

// UpdateResult describes one update attempt. Changed is false when the local
// copy is already current.
type UpdateResult struct {
	Changed      bool
	LastModified time.Time
}

type fileMeta struct {
	Edition      string    `json:"edition"`
	SHA256       string    `json:"sha256"`
	LastModified time.Time `json:"last_modified"`
	InstalledAt  time.Time `json:"installed_at"`
}

// Updater downloads a GeoLite2/GeoIP2 database with the current MaxMind
// permalink API and installs it atomically. The license key is sent only as
// Basic authentication to an allowlisted host.
type Updater struct {
	cfg     config.MaxMindConfig
	db      *Database
	log     *slog.Logger
	client  *http.Client
	head    *http.Client
	hosts   map[string]struct{}
	mu      sync.Mutex
	baseURL string
}

func NewUpdater(cfg config.MaxMindConfig, db *Database, log *slog.Logger) *Updater {
	if log == nil {
		log = slog.Default()
	}
	hosts := map[string]struct{}{}
	for _, host := range defaultRedirectHosts {
		hosts[strings.ToLower(host)] = struct{}{}
	}
	for _, host := range cfg.ExtraRedirectHosts {
		hosts[strings.ToLower(host)] = struct{}{}
	}
	u := &Updater{
		cfg:     cfg,
		db:      db,
		log:     log,
		hosts:   hosts,
		baseURL: cfg.DownloadBase,
	}
	u.client = &http.Client{
		Timeout:       downloadTimeout,
		CheckRedirect: u.checkRedirect,
		Transport:     newTransport(),
	}
	// HEAD follows the same allowlisted redirects as GET. MaxMind's permalink
	// answers with a redirect; Last-Modified is on the final object, and a
	// HEAD does not count as a database download.
	u.head = &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: u.checkRedirect,
		Transport:     newTransport(),
	}
	return u
}

func newTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          2,
	}
}

// Loop checks for a newer build until ctx is cancelled. HEAD requests do not
// count against MaxMind's download limit.
func (u *Updater) Loop(ctx context.Context) {
	ticker := time.NewTicker(u.cfg.UpdateInterval.Std())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := u.Update(ctx); err != nil {
				u.log.Error("geoip update failed", "err", redact(err.Error(), u.cfg))
			}
		}
	}
}

// Update downloads the configured edition when the remote build is newer.
func (u *Updater) Update(ctx context.Context) (UpdateResult, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	unlock, err := lockDatabase(u.cfg.DatabasePath)
	if err != nil {
		return UpdateResult{}, err
	}
	defer unlock()

	meta, _ := readMeta(metaPath(u.cfg.DatabasePath))
	remoteMod, status, headErr := u.remoteLastModified(ctx)
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return UpdateResult{}, headErr
	}
	if headErr == nil && !remoteMod.IsZero() && !meta.LastModified.IsZero() && !remoteMod.After(meta.LastModified.Add(time.Second)) {
		u.log.Info("geoip database is current", "edition", u.cfg.EditionID, "last_modified", meta.LastModified.UTC().Format(time.RFC3339))
		return UpdateResult{LastModified: meta.LastModified}, nil
	}
	if headErr != nil {
		u.log.Warn("geoip freshness check failed; attempting download", "err", redact(headErr.Error(), u.cfg))
	}

	archive, err := os.CreateTemp(filepath.Dir(u.cfg.DatabasePath), ".geoip-archive-*")
	if err != nil {
		if err := os.MkdirAll(filepath.Dir(u.cfg.DatabasePath), 0o750); err != nil {
			return UpdateResult{}, err
		}
		archive, err = os.CreateTemp(filepath.Dir(u.cfg.DatabasePath), ".geoip-archive-*")
		if err != nil {
			return UpdateResult{}, err
		}
	}
	defer os.Remove(archive.Name())
	defer archive.Close()

	modified, err := u.download(ctx, "tar.gz", archive)
	if err != nil {
		return UpdateResult{}, err
	}
	if err := archive.Close(); err != nil {
		return UpdateResult{}, err
	}
	sum, err := hashFile(archive.Name())
	if err != nil {
		return UpdateResult{}, err
	}
	want, err := u.downloadSHA256(ctx)
	if err != nil {
		return UpdateResult{}, err
	}
	if !strings.EqualFold(sum, want) {
		return UpdateResult{}, errors.New("downloaded archive failed sha256 verification")
	}
	mmdb, err := extractMMDB(archive.Name(), u.cfg.EditionID)
	if err != nil {
		return UpdateResult{}, err
	}
	if err := installMMDB(u.cfg.DatabasePath, u.cfg.EditionID, mmdb); err != nil {
		return UpdateResult{}, err
	}
	if modified.IsZero() {
		modified = remoteMod
	}
	next := fileMeta{
		Edition:      u.cfg.EditionID,
		SHA256:       sum,
		LastModified: modified.UTC(),
		InstalledAt:  time.Now().UTC(),
	}
	if err := writeMeta(metaPath(u.cfg.DatabasePath), next); err != nil {
		return UpdateResult{}, err
	}
	if err := u.db.Reload(); err != nil {
		return UpdateResult{}, err
	}
	u.log.Info("geoip database updated", "edition", u.cfg.EditionID, "sha256", sum)
	return UpdateResult{Changed: true, LastModified: next.LastModified}, nil
}

func (u *Updater) remoteLastModified(ctx context.Context) (time.Time, int, error) {
	req, err := u.newRequest(ctx, http.MethodHead, "tar.gz")
	if err != nil {
		return time.Time{}, 0, err
	}
	resp, err := u.head.Do(req)
	if err != nil {
		return time.Time{}, 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, resp.StatusCode, statusError(resp)
	}
	if resp.Header.Get("Last-Modified") == "" {
		return time.Time{}, resp.StatusCode, nil
	}
	mod, err := http.ParseTime(resp.Header.Get("Last-Modified"))
	if err != nil {
		return time.Time{}, resp.StatusCode, nil
	}
	return mod, resp.StatusCode, nil
}

func (u *Updater) download(ctx context.Context, suffix string, dst *os.File) (time.Time, error) {
	req, err := u.newRequest(ctx, http.MethodGet, suffix)
	if err != nil {
		return time.Time{}, err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return time.Time{}, redactErr(err, u.cfg)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, statusError(resp)
	}
	n, err := io.Copy(dst, io.LimitReader(resp.Body, maxArchiveBytes+1))
	if err != nil {
		return time.Time{}, err
	}
	if n > maxArchiveBytes {
		return time.Time{}, errors.New("geoip archive exceeds size limit")
	}
	if resp.Header.Get("Last-Modified") == "" {
		return time.Time{}, nil
	}
	mod, err := http.ParseTime(resp.Header.Get("Last-Modified"))
	if err != nil {
		return time.Time{}, nil
	}
	return mod, nil
}

func (u *Updater) downloadSHA256(ctx context.Context) (string, error) {
	req, err := u.newRequest(ctx, http.MethodGet, "tar.gz.sha256")
	if err != nil {
		return "", err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return "", redactErr(err, u.cfg)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", statusError(resp)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	return parseSHA256(string(body))
}

func (u *Updater) newRequest(ctx context.Context, method, suffix string) (*http.Request, error) {
	raw, err := downloadURL(u.baseURL, u.cfg.EditionID, suffix)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, raw, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(u.cfg.AccountID, u.cfg.LicenseKey)
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/gzip, application/octet-stream, */*")
	return req, nil
}

func (u *Updater) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return errors.New("too many geoip download redirects")
	}
	if req.URL.Scheme != "https" && !strings.HasPrefix(u.baseURL, "http://") {
		return fmt.Errorf("refusing non-https geoip redirect to %s", req.URL.Host)
	}
	host := strings.ToLower(req.URL.Hostname())
	if _, ok := u.hosts[host]; !ok {
		return fmt.Errorf("refusing geoip redirect host %s", host)
	}
	// Go copies Authorization onto a redirect when the hostnames match, including
	// two different ports on 127.0.0.1. Drop it unless the scheme, host, and
	// port are all unchanged. Presigned storage URLs must not receive the license key.
	if len(via) > 0 && !sameOrigin(via[len(via)-1].URL, req.URL) {
		req.Header.Del("Authorization")
	}
	return nil
}

func downloadURL(base, edition, suffix string) (string, error) {
	if !editionPattern(edition) {
		return "", fmt.Errorf("invalid edition %q", edition)
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	u.Path = path.Join(u.Path, "geoip/databases", edition, "download")
	q := u.Query()
	q.Set("suffix", suffix)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func editionPattern(edition string) bool {
	if edition == "" || len(edition) > 64 {
		return false
	}
	for _, r := range edition {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

func sameOrigin(a, b *url.URL) bool {
	return originKey(a) == originKey(b)
}

func originKey(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Hostname()) + ":" + port
}

func parseSHA256(text string) (string, error) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		m := sha256Pattern.FindStringSubmatch(line)
		if m != nil {
			return strings.ToLower(m[1]), nil
		}
	}
	return "", errors.New("sha256 file did not contain a hash")
}

func extractMMDB(archivePath, edition string) ([]byte, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("open geoip archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	want := edition + ".mmdb"
	var found []byte
	entries := 0
	uncompressed := int64(0)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		entries++
		if entries > maxTarEntries {
			return nil, errors.New("geoip archive has too many entries")
		}
		name := path.Clean(hdr.Name)
		if name == "" || strings.HasPrefix(name, "..") || path.IsAbs(name) || strings.Contains(name, "..") {
			return nil, fmt.Errorf("geoip archive contains an unsafe path %q", hdr.Name)
		}
		if hdr.Size < 0 || uncompressed+hdr.Size > maxUncompressed {
			return nil, errors.New("geoip archive exceeds uncompressed size limit")
		}
		uncompressed += hdr.Size
		if path.Base(name) != want {
			if _, err := io.Copy(io.Discard, io.LimitReader(tr, hdr.Size)); err != nil {
				return nil, err
			}
			continue
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA && hdr.Typeflag != 0 {
			return nil, fmt.Errorf("refusing non-regular geoip file %q", hdr.Name)
		}
		if found != nil {
			return nil, errors.New("geoip archive contains more than one database")
		}
		buf := bytes.NewBuffer(make([]byte, 0, hdr.Size))
		if _, err := io.Copy(buf, io.LimitReader(tr, hdr.Size)); err != nil {
			return nil, err
		}
		found = buf.Bytes()
	}
	if found == nil {
		return nil, fmt.Errorf("archive does not contain %s", want)
	}
	return found, nil
}

func installMMDB(dest, edition string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".geoip-db-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	installed := false
	defer func() {
		if !installed {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o640); err != nil {
		return err
	}
	reader, err := maxminddb.Open(tmpName)
	if err != nil {
		return fmt.Errorf("downloaded file is not a MaxMind database: %w", err)
	}
	dbType := reader.Metadata.DatabaseType
	epoch := reader.Metadata.BuildEpoch
	reader.Close()
	if dbType != edition {
		return fmt.Errorf("downloaded database type %q, want %q", dbType, edition)
	}
	if epoch == 0 {
		return errors.New("downloaded database has no build epoch")
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return err
	}
	installed = true
	return nil
}

func metaPath(databasePath string) string { return databasePath + ".meta.json" }

func readMeta(path string) (fileMeta, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return fileMeta{}, err
	}
	var meta fileMeta
	if err := json.Unmarshal(b, &meta); err != nil {
		return fileMeta{}, err
	}
	return meta, nil
}

func writeMeta(path string, meta fileMeta) error {
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".geoip-meta-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	installed := false
	defer func() {
		if !installed {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	installed = true
	return nil
}

func lockDatabase(databasePath string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(databasePath), 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(databasePath+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

func statusError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	text := strings.Join(strings.Fields(string(body)), " ")
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return errors.New("MaxMind rejected the account ID or license key. This API requires both for Basic authentication; providing only the license key is not sufficient.")
	case http.StatusForbidden:
		return fmt.Errorf("MaxMind refused the download of this database: %s", text)
	case http.StatusNotFound:
		return fmt.Errorf("MaxMind does not have this database version: %s", text)
	case http.StatusTooManyRequests:
		return errors.New("maxMind download rate limit exceeded; will retry during the next update cycle")
	default:
		return fmt.Errorf("MaxMind download failed: HTTP %d %s", resp.StatusCode, text)
	}
}

func redact(text string, cfg config.MaxMindConfig) string {
	if cfg.LicenseKey != "" {
		text = strings.ReplaceAll(text, cfg.LicenseKey, "[redacted]")
	}
	if cfg.AccountID != "" {
		text = strings.ReplaceAll(text, cfg.AccountID, "[redacted]")
	}
	return redactURLQuery(text)
}

// redactURLQuery hides presigned download URLs. Those query strings are
// credentials for the object store even though they are short-lived.
func redactURLQuery(text string) string {
	var b strings.Builder
	b.Grow(len(text))
	rest := text
	for {
		idx := strings.Index(rest, "://")
		if idx < 0 {
			b.WriteString(rest)
			break
		}
		start := idx
		for start > 0 && !isURLDelimiter(rest[start-1]) {
			start--
		}
		b.WriteString(rest[:start])
		end := start
		for end < len(rest) && !isURLDelimiter(rest[end]) {
			end++
		}
		raw := rest[start:end]
		if q := strings.IndexByte(raw, '?'); q >= 0 {
			raw = raw[:q] + "?[redacted]"
		}
		b.WriteString(raw)
		rest = rest[end:]
	}
	return b.String()
}

func isURLDelimiter(c byte) bool {
	switch c {
	case ' ', '\t', '\r', '\n', '"', '\'', '<', '>':
		return true
	default:
		return false
	}
}

func redactErr(err error, cfg config.MaxMindConfig) error {
	if err == nil {
		return nil
	}
	return errors.New(redact(err.Error(), cfg))
}

// hashOf is used by tests that build an archive in memory.
func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
