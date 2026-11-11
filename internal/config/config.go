package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultListen         = "127.0.0.1:8088"
	DefaultEdition        = "GeoLite2-Country"
	DefaultDownloadBase   = "https://download.maxmind.com"
	DefaultUpdateInterval = 6 * time.Hour
	DefaultMaxStale       = 7 * 24 * time.Hour
	DefaultCodeTTL        = 60 * time.Second
	DefaultClearanceTTL   = 30 * time.Minute
	DefaultCookieName     = "ra_clearance"
	DefaultCodeQuery      = "ra_code"
)

// Config is loaded from a local file. The license key and signing key are
// never taken from a request.
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	MaxMind   MaxMindConfig   `yaml:"maxmind"`
	Policy    PolicyConfig    `yaml:"policy"`
	Gate      GateConfig      `yaml:"gate"`
	Token     TokenConfig     `yaml:"token"`
	BlockPage BlockPageConfig `yaml:"block_page"`
	Log       LogConfig       `yaml:"log"`

	ConfigDir     string `yaml:"-"`
	worldReadable bool
}

type ServerConfig struct {
	Listen          string   `yaml:"listen"`
	AllowPublicBind bool     `yaml:"allow_public_bind"`
	TrustedProxies  []string `yaml:"trusted_proxies"`
	RealIPHeader    string   `yaml:"real_ip_header"`
}

type MaxMindConfig struct {
	AccountID          string   `yaml:"account_id"`
	LicenseKey         string   `yaml:"license_key"`
	EditionID          string   `yaml:"edition_id"`
	DownloadBase       string   `yaml:"download_base"`
	DatabasePath       string   `yaml:"database_path"`
	UpdateEnabled      bool     `yaml:"update_enabled"`
	UpdateInterval     Duration `yaml:"update_interval"`
	MaxStale           Duration `yaml:"max_stale"`
	ExtraRedirectHosts []string `yaml:"extra_redirect_hosts"`
}

type PolicyConfig struct {
	DenyCountries           []string `yaml:"deny_countries"`
	DenySubdivisions        []string `yaml:"deny_subdivisions"`
	AlwaysDenyIPs           []string `yaml:"always_deny_ips"`
	AlwaysAllowIPs          []string `yaml:"always_allow_ips"`
	AllowEmptyBlacklist     bool     `yaml:"allow_empty_blacklist"`
	UnknownAction           string   `yaml:"unknown_action"`
	PrivateIPAction         string   `yaml:"private_ip_action"`
	CheckRegisteredCountry  bool     `yaml:"check_registered_country"`
	CheckRepresentedCountry bool     `yaml:"check_represented_country"`
}

type GateConfig struct {
	CallbackURL       string `yaml:"callback_url"`
	SuccessPath       string `yaml:"success_path"`
	EntryPath         string `yaml:"entry_path"`
	AllowInsecureHTTP bool   `yaml:"allow_insecure_http"`
	Audience          string `yaml:"-"`
}

type TokenConfig struct {
	SigningKey   string   `yaml:"signing_key"`
	CodeTTL      Duration `yaml:"code_ttl"`
	ClearanceTTL Duration `yaml:"clearance_ttl"`
	CookieName   string   `yaml:"cookie_name"`
	CodeQuery    string   `yaml:"code_query"`
	CookieSecure bool     `yaml:"cookie_secure"`
	BindIP       bool     `yaml:"bind_ip"`
	IPv4Prefix   int      `yaml:"ipv4_prefix"`
	IPv6Prefix   int      `yaml:"ipv6_prefix"`
	Key          []byte   `yaml:"-"`
}

type BlockPageConfig struct {
	SiteName string `yaml:"site_name"`
	Title    string `yaml:"title"`
	Message  string `yaml:"message"`
	English  string `yaml:"english"`
	Lang     string `yaml:"lang"`
}

type LogConfig struct {
	Level string `yaml:"level"`
}

// Duration is a YAML string parsed with time.ParseDuration.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var raw string
	if err := value.Decode(&raw); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("无效的时长 %q: %w", raw, err)
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) Std() time.Duration { return time.Duration(d) }

func (c *Config) WorldReadable() bool { return c.worldReadable }

func defaults() Config {
	return Config{
		Server: ServerConfig{
			Listen:         DefaultListen,
			TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
			RealIPHeader:   "X-Real-IP",
		},
		MaxMind: MaxMindConfig{
			EditionID:      DefaultEdition,
			DownloadBase:   DefaultDownloadBase,
			DatabasePath:   "data/GeoLite2-Country.mmdb",
			UpdateEnabled:  true,
			UpdateInterval: Duration(DefaultUpdateInterval),
			MaxStale:       Duration(DefaultMaxStale),
		},
		Policy: PolicyConfig{
			UnknownAction:           "deny",
			PrivateIPAction:         "deny",
			CheckRegisteredCountry:  true,
			CheckRepresentedCountry: true,
		},
		Gate: GateConfig{
			EntryPath:   "/_ra/gate",
			SuccessPath: "/",
		},
		Token: TokenConfig{
			CodeTTL:      Duration(DefaultCodeTTL),
			ClearanceTTL: Duration(DefaultClearanceTTL),
			CookieName:   DefaultCookieName,
			CodeQuery:    DefaultCodeQuery,
			CookieSecure: true,
			BindIP:       true,
			IPv4Prefix:   32,
			IPv6Prefix:   128,
		},
		BlockPage: BlockPageConfig{
			Title:   "Not accessible in your current region.",
			Message: "This service is not available in your current region.",
			English: "This service is not available in your current region.",
			Lang:    "en-US",
		},
		Log: LogConfig{Level: "info"},
	}
}

// Load reads, normalizes, and validates the configuration file.
func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, fmt.Errorf("open configuration file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	cfg := defaults()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing configuration file: %w", err)
	}
	cfg.ConfigDir = filepath.Dir(abs)
	cfg.normalize()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg.worldReadable = info.Mode().Perm()&0o007 != 0
	return &cfg, nil
}

func (c *Config) normalize() {
	c.Server.Listen = strings.TrimSpace(c.Server.Listen)
	c.Server.RealIPHeader = strings.TrimSpace(c.Server.RealIPHeader)
	c.MaxMind.AccountID = strings.TrimSpace(c.MaxMind.AccountID)
	c.MaxMind.LicenseKey = strings.TrimSpace(c.MaxMind.LicenseKey)
	c.MaxMind.EditionID = strings.TrimSpace(c.MaxMind.EditionID)
	c.MaxMind.DownloadBase = strings.TrimRight(strings.TrimSpace(c.MaxMind.DownloadBase), "/")
	c.MaxMind.DatabasePath = strings.TrimSpace(c.MaxMind.DatabasePath)
	hosts := make([]string, 0, len(c.MaxMind.ExtraRedirectHosts))
	seen := map[string]struct{}{}
	for _, host := range c.MaxMind.ExtraRedirectHosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	c.MaxMind.ExtraRedirectHosts = hosts
	if c.MaxMind.DatabasePath != "" && !filepath.IsAbs(c.MaxMind.DatabasePath) {
		c.MaxMind.DatabasePath = filepath.Join(c.ConfigDir, c.MaxMind.DatabasePath)
	}
	c.MaxMind.DatabasePath = filepath.Clean(c.MaxMind.DatabasePath)
	c.Policy.DenyCountries = upperCodes(c.Policy.DenyCountries)
	c.Policy.DenySubdivisions = upperCodes(c.Policy.DenySubdivisions)
	c.Policy.UnknownAction = strings.ToLower(strings.TrimSpace(c.Policy.UnknownAction))
	c.Policy.PrivateIPAction = strings.ToLower(strings.TrimSpace(c.Policy.PrivateIPAction))
	c.Gate.CallbackURL = strings.TrimSpace(c.Gate.CallbackURL)
	c.Gate.SuccessPath = strings.TrimSpace(c.Gate.SuccessPath)
	c.Gate.EntryPath = strings.TrimSpace(c.Gate.EntryPath)
	c.Token.SigningKey = strings.TrimSpace(c.Token.SigningKey)
	c.Token.CookieName = strings.TrimSpace(c.Token.CookieName)
	c.Token.CodeQuery = strings.TrimSpace(c.Token.CodeQuery)
	c.BlockPage.Title = strings.TrimSpace(c.BlockPage.Title)
	c.BlockPage.Message = strings.TrimSpace(c.BlockPage.Message)
	c.BlockPage.English = strings.TrimSpace(c.BlockPage.English)
	c.BlockPage.Lang = strings.TrimSpace(c.BlockPage.Lang)
	c.Log.Level = strings.ToLower(strings.TrimSpace(c.Log.Level))
	if u, err := url.Parse(c.Gate.CallbackURL); err == nil {
		c.Gate.Audience = u.Host
	}
}

func upperCodes(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, item := range in {
		item = strings.ToUpper(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

// Validate checks the normalized configuration and decodes the signing key.
func (c *Config) Validate() error {
	var errs []string
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf(format, args...))
	}

	if err := validateListen(c.Server.Listen, c.Server.AllowPublicBind); err != nil {
		add("%s", err.Error())
	}
	if c.Server.RealIPHeader == "" || strings.ContainsAny(c.Server.RealIPHeader, " \t\r\n:") {
		add("server.real_ip_header is invalid")
	}
	for _, cidr := range c.Server.TrustedProxies {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			add("server.trusted_proxies contains an invalid network segment: %q", cidr)
		}
	}

	if c.MaxMind.UpdateEnabled {
		if isPlaceholder(c.MaxMind.AccountID) || !accountIDPattern(c.MaxMind.AccountID) {
			add("The maxmind.account_id must be your MaxMind account ID (numeric only). The current download API uses your account ID and license key for Basic authentication.")
		}
		if isPlaceholder(c.MaxMind.LicenseKey) || len(c.MaxMind.LicenseKey) < 12 || strings.ContainsAny(c.MaxMind.LicenseKey, " \t\r\n") {
			add("The maxmind.license_key must be provided in the configuration file and cannot be a placeholder.")
		}
	}
	if !knownEdition(c.MaxMind.EditionID) {
		add("The maxmind.edition_id only allows GeoLite2-Country, GeoLite2-City, GeoIP2-Country, GeoIP2-City")
	}
	if err := validateDownloadBase(c.MaxMind.DownloadBase); err != nil {
		add("%s", err.Error())
	} else if u, err := url.Parse(c.MaxMind.DownloadBase); err != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		add("maxmind.download_base must not include a path or query parameters.")
	}
	for _, host := range c.MaxMind.ExtraRedirectHosts {
		if !redirectHost(host) {
			add("maxmind.extra_redirect_hosts contains an invalid host name %q. Enter only the host name; do not include wildcards, ports, or full URLs.", host)
		}
	}
	if c.MaxMind.DatabasePath == "" || !strings.HasSuffix(c.MaxMind.DatabasePath, ".mmdb") {
		add("maxmind.database_path must end with .mmdb")
	}
	if c.MaxMind.UpdateInterval.Std() < time.Hour {
		add("maxmind.update_interval cannot be shorter than 1h, to avoid triggering MaxMind's rate limits.")
	}
	if c.MaxMind.MaxStale.Std() < 24*time.Hour {
		add("maxmind.max_stale cannot be less than 24h")
	}

	if len(c.Policy.DenyCountries)+len(c.Policy.DenySubdivisions)+len(c.Policy.AlwaysDenyIPs) == 0 && !c.Policy.AllowEmptyBlacklist {
		add("The blacklist is empty. Please configure `policy.deny_countries`; set `allow_empty_blacklist: true` only if you explicitly accept the policy of not blocking by region.")
	}
	for _, cc := range c.Policy.DenyCountries {
		if !countryCode(cc) {
			add("policy.deny_countries contains an invalid country code %q，expected ISO 3166-1 alpha-2", cc)
		}
	}
	for _, sub := range c.Policy.DenySubdivisions {
		if !subdivisionCode(sub) {
			add("policy.deny_subdivisions contains an invalid area code %q，e.g., US-CA", sub)
		}
	}
	for _, item := range append(append([]string{}, c.Policy.AlwaysDenyIPs...), c.Policy.AlwaysAllowIPs...) {
		if _, err := parseIPOrPrefix(item); err != nil {
			add("Policy IP invalid: %s", item)
		}
	}
	if c.Policy.UnknownAction != "deny" && c.Policy.UnknownAction != "allow" {
		add("policy.unknown_action can only be 'deny' or 'allow'")
	}
	if c.Policy.PrivateIPAction != "deny" && c.Policy.PrivateIPAction != "allow" {
		add("policy.private_ip_action can only be 'deny' or 'allow'")
	}

	callback, err := url.Parse(c.Gate.CallbackURL)
	if err != nil || callback.Host == "" || callback.User != nil || callback.Fragment != "" {
		add("gate.callback_url must be an absolute URL containing neither user information nor a fragment.")
	} else {
		if callback.Scheme != "https" && !(c.Gate.AllowInsecureHTTP && callback.Scheme == "http") {
			add("gate.callback_url must use HTTPS. Setting `allow_insecure_http: true` is permitted only for local debugging.")
		}
		if callback.Path == "" || callback.Path == "/" || strings.Contains(callback.Path, "..") {
			add("The path for `gate.callback_url` must be the callback URL on the target site—for example, /_ra/callback")
		}
		if callback.Path == c.Gate.SuccessPath {
			add("The path for `gate.callback_url` cannot be the same as `success_path`; otherwise, the verification callback cannot be completed.")
		}
	}
	if !localPath(c.Gate.SuccessPath) {
		add("The `gate.success_path` must be an absolute path on the target site; it cannot be a URL pointing to an external site.")
	}
	if !localPath(c.Gate.EntryPath) {
		add("The `gate.entry_path` must be an absolute path within this site.")
	}
	if c.Gate.SuccessPath == c.Gate.EntryPath {
		add("gate.success_path cannot be the same as entry_path")
	}

	key, err := decodeSigningKey(c.Token.SigningKey)
	if err != nil {
		add("token.signing_key: %s", err.Error())
	} else if isPlaceholder(c.Token.SigningKey) || lowEntropy(key) {
		add("`token.signing_key` must be a random key generated using `openssl rand -base64 32`; placeholders are not permitted.")
	} else if c.MaxMind.LicenseKey != "" && string(key) == c.MaxMind.LicenseKey {
		add("token.signing_key cannot be the same as the authorization key.")
	} else {
		c.Token.Key = key
	}
	if c.Token.CodeTTL.Std() < 10*time.Second || c.Token.CodeTTL.Std() > 5*time.Minute {
		add("token.code_ttl must be between 10s and 5m.")
	}
	if c.Token.ClearanceTTL.Std() < time.Minute || c.Token.ClearanceTTL.Std() > 24*time.Hour {
		add("token.clearance_ttl must be between 1m and 24h")
	}
	if !tokenName(c.Token.CookieName) || !tokenName(c.Token.CodeQuery) {
		add("token.cookie_name and token.code_query can only contain letters, numbers, underscores, and hyphens.")
	}
	if c.Token.BindIP {
		if c.Token.IPv4Prefix < 24 || c.Token.IPv4Prefix > 32 {
			add("token.ipv4_prefix must be between 24 and 32")
		}
		if c.Token.IPv6Prefix < 48 || c.Token.IPv6Prefix > 128 {
			add("token.ipv6_prefix must be between 48 and 128")
		}
	} else {
		add("`token.bind_ip` cannot be disabled. If it is disabled, the token could be replayed from other IP addresses while it remains valid.")
	}
	if c.BlockPage.Title == "" || c.BlockPage.Message == "" {
		add("block_page.title and block_page.message cannot be empty")
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		add("log.level can only be debug, info, warn, or error")
	}

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("Invalid configuration:\n- %s", strings.Join(errs, "\n- "))
}

func validateListen(listen string, allowPublic bool) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("server.listen is invalid: %s", listen)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("the host for server.listen must be an IP address or 'localhost'")
	}
	if !ip.IsLoopback() && !allowPublic {
		return fmt.Errorf("by default, `server.listen` can only bind to the loopback address. Exposing a detection port to the public internet would allow traffic to bypass Nginx; only set `allow_public_bind: true` if it is strictly necessary")
	}
	return nil
}

func validateDownloadBase(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return fmt.Errorf("maxmind.download_base is invalid")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("maxmind.download_base must be https")
	}
	host := strings.ToLower(u.Hostname())
	if host != "download.maxmind.com" && host != "updates.maxmind.com" {
		return fmt.Errorf("maxmind.download_base must be download.maxmind.com or updates.maxmind.com")
	}
	return nil
}

func redirectHost(host string) bool {
	if host == "" || len(host) > 253 || strings.Contains(host, "*") {
		return false
	}
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
		default:
			return false
		}
	}
	return !strings.HasPrefix(host, ".") && !strings.HasSuffix(host, ".") && !strings.Contains(host, "..")
}

func knownEdition(edition string) bool {
	switch edition {
	case "GeoLite2-Country", "GeoLite2-City", "GeoIP2-Country", "GeoIP2-City":
		return true
	default:
		return false
	}
}

func countryCode(cc string) bool {
	if len(cc) != 2 {
		return false
	}
	for _, r := range cc {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

func subdivisionCode(code string) bool {
	parts := strings.Split(code, "-")
	if len(parts) != 2 || !countryCode(parts[0]) || len(parts[1]) < 1 || len(parts[1]) > 3 {
		return false
	}
	for _, r := range parts[1] {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func localPath(p string) bool {
	if p == "" || p[0] != '/' || strings.HasPrefix(p, "//") {
		return false
	}
	if strings.Contains(p, "..") || strings.ContainsAny(p, "\\?# \t") {
		return false
	}
	return true
}

func tokenName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

func accountIDPattern(id string) bool {
	if id == "" || len(id) > 12 {
		return false
	}
	for _, r := range id {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isPlaceholder(value string) bool {
	low := strings.ToLower(value)
	return value == "" ||
		strings.Contains(low, "replace") ||
		strings.Contains(low, "changeme") ||
		strings.Contains(low, "change-me") ||
		strings.Contains(low, "your_") ||
		strings.Contains(low, "example")
}

func decodeSigningKey(raw string) ([]byte, error) {
	switch {
	case strings.HasPrefix(raw, "base64:"):
		return decodeBase64(strings.TrimPrefix(raw, "base64:"))
	case strings.HasPrefix(raw, "hex:"):
		return decodeHex(strings.TrimPrefix(raw, "hex:"))
	case isHexKey(raw):
		return decodeHex(raw)
	default:
		if decoded, err := decodeBase64(raw); err == nil && len(decoded) >= 32 {
			return decoded, nil
		}
		if len(raw) >= 32 {
			return []byte(raw), nil
		}
		return nil, fmt.Errorf("at least 32 bytes are required. Generation method: openssl rand -base64 32")
	}
}

func decodeBase64(raw string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(raw)
}

func decodeHex(raw string) ([]byte, error) {
	b, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid hexadecimal key")
	}
	if len(b) < 32 {
		return nil, fmt.Errorf("at least 32 bytes are required")
	}
	return b, nil
}

func isHexKey(raw string) bool {
	if len(raw) < 64 || len(raw)%2 != 0 {
		return false
	}
	for _, r := range raw {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

func lowEntropy(b []byte) bool {
	if len(b) < 32 {
		return true
	}
	seen := map[byte]struct{}{}
	for _, c := range b {
		seen[c] = struct{}{}
	}
	return len(seen) < 8
}

func parseIPOrPrefix(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "/") {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr = addr.Unmap()
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return addr.Prefix(bits)
}
