package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"restricted-access/internal/config"
	"restricted-access/internal/geo"
	"restricted-access/internal/httpapi"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "restricted-access: %s\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(os.Stderr, usage)
		if len(args) == 0 {
			return errors.New("missing required argument")
		}
		return nil
	}
	switch args[0] {
	case "serve":
		return cmdServe(args[1:])
	case "update":
		return cmdUpdate(args[1:])
	case "check-config":
		return cmdCheck(args[1:])
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command: %q", args[0])
	}
}

const usage = `Usage:
  restricted-access serve -config <file>
  restricted-access update -config <file>
  restricted-access check-config -config <file>

serve        Enable region checks on the loopback address, with automatic GeoIP database updates based on configuration.
update       Check and update the database now
check-config Check the configuration; do not print the license key or signing key.
`

func cmdServe(args []string) error {
	path, err := configPath(args)
	if err != nil {
		return err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	logger := newLogger(cfg.Log.Level)
	if err := checkConfigPerms(path, logger, true); err != nil {
		return err
	}
	if cfg.Server.AllowPublicBind {
		logger.Warn("The monitoring service is permitted to bind to non-loopback addresses. This port must not be exposed outside of Nginx; otherwise, the origin server could potentially bypass site configurations.")
	}

	db := geo.NewDatabase(cfg.MaxMind.DatabasePath, cfg.MaxMind.EditionID, cfg.MaxMind.MaxStale.Std())
	defer db.Close()
	if err := db.Reload(); err != nil {
		logger.Warn("geoip database is not ready", "err", err.Error())
	}
	updater := geo.NewUpdater(cfg.MaxMind, db, logger)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if !db.Ready() {
		if !cfg.MaxMind.UpdateEnabled {
			return errors.New("the GeoIP database is unavailable, and automatic updates are disabled in the configuration. Access cannot be granted until the region can be verified")
		}
		logger.Info("geoip database missing or stale; downloading before serving")
		updateCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		_, updateErr := updater.Update(updateCtx)
		cancel()
		if updateErr != nil {
			logger.Error("initial geoip update failed; requests stay denied until a later update succeeds", "err", updateErr.Error())
		}
	}
	if cfg.MaxMind.UpdateEnabled {
		go updater.Loop(ctx)
	} else if !db.Ready() {
		return errors.New("the GeoIP database is unavailable")
	}

	api, err := httpapi.New(cfg, db, logger)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog: log.New(secretRedactor{
			next: os.Stderr,
			keys: []string{cfg.Token.CodeQuery, cfg.Token.CookieName},
		}, "", 0),
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.Server.Listen)
		err := server.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return <-errCh
	case err := <-errCh:
		return err
	}
}

func cmdUpdate(args []string) error {
	path, err := configPath(args)
	if err != nil {
		return err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	logger := newLogger(cfg.Log.Level)
	if err := checkConfigPerms(path, logger, false); err != nil {
		return err
	}
	if !cfg.MaxMind.UpdateEnabled {
		return errors.New("maxmind.update_enabled is set to false; no updates can be performed")
	}
	db := geo.NewDatabase(cfg.MaxMind.DatabasePath, cfg.MaxMind.EditionID, cfg.MaxMind.MaxStale.Std())
	defer db.Close()
	updater := geo.NewUpdater(cfg.MaxMind, db, logger)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	result, err := updater.Update(ctx)
	if err != nil {
		return err
	}
	if result.Changed {
		fmt.Printf("Database updated, build time %s\n", result.LastModified.UTC().Format(time.RFC3339))
	} else {
		fmt.Printf("The database is already at the current version; build time %s\n", result.LastModified.UTC().Format(time.RFC3339))
	}
	return nil
}

func cmdCheck(args []string) error {
	path, err := configPath(args)
	if err != nil {
		return err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	logger := newLogger(cfg.Log.Level)
	if err := checkConfigPerms(path, logger, false); err != nil {
		return err
	}
	callbackHost := cfg.Gate.Audience
	fmt.Printf("配置可用\n")
	fmt.Printf("listen: %s\n", cfg.Server.Listen)
	fmt.Printf("edition: %s\n", cfg.MaxMind.EditionID)
	fmt.Printf("database: %s\n", cfg.MaxMind.DatabasePath)
	fmt.Printf("update: %t interval %s max_stale %s\n", cfg.MaxMind.UpdateEnabled, cfg.MaxMind.UpdateInterval.Std(), cfg.MaxMind.MaxStale.Std())
	fmt.Printf("deny_countries: %d\n", len(cfg.Policy.DenyCountries))
	fmt.Printf("deny_subdivisions: %d\n", len(cfg.Policy.DenySubdivisions))
	fmt.Printf("callback_host: %s\n", callbackHost)
	fmt.Printf("success_path: %s\n", cfg.Gate.SuccessPath)
	fmt.Printf("entry_path: %s\n", cfg.Gate.EntryPath)
	fmt.Printf("cookie: %s secure %t\n", cfg.Token.CookieName, cfg.Token.CookieSecure)
	fmt.Printf("bind_ip: ipv4 /%d ipv6 /%d\n", cfg.Token.IPv4Prefix, cfg.Token.IPv6Prefix)
	return nil
}

func configPath(args []string) (string, error) {
	path := ""
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "-config" || args[i] == "--config":
			if i+1 >= len(args) {
				return "", errors.New("-config File path required")
			}
			i++
			path = args[i]
		case strings.HasPrefix(args[i], "-config="):
			path = strings.TrimPrefix(args[i], "-config=")
		case strings.HasPrefix(args[i], "--config="):
			path = strings.TrimPrefix(args[i], "--config=")
		default:
			return "", fmt.Errorf("unrecognized parameter: %q", args[i])
		}
	}
	if path == "" {
		return "", errors.New("you must use -config to specify a configuration file")
	}
	return path, nil
}

func checkConfigPerms(path string, logger *slog.Logger, strict bool) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	mode := info.Mode().Perm()
	if mode&0o002 != 0 {
		return fmt.Errorf("configuration file %s is writable by other users (%04o). Please change it to 0640, with root as the owner and the user running the application as the group", path, mode)
	}
	if mode&0o007 != 0 {
		logger.Warn("The configuration file is readable by other users. It contains license keys and signing keys; please change its permissions to 0640.", "path", path, "mode", fmt.Sprintf("%04o", mode))
		if strict {
			logger.Warn("The system continues to boot, but other users on the local machine can read the signing key. While the signing key cannot bypass regional restrictions, it is sufficient to forge access credentials.")
		}
	}
	return nil
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

// secretRedactor removes one-time codes and clearance cookies from the
// net/http server log. It does not try to recover or print those values.
type secretRedactor struct {
	next io.Writer
	keys []string
}

func (s secretRedactor) Write(p []byte) (int, error) {
	text := string(p)
	for _, key := range s.keys {
		text = redactQueryValue(text, key)
	}
	if _, err := io.WriteString(s.next, text); err != nil {
		return 0, err
	}
	return len(p), nil
}

func redactQueryValue(text, key string) string {
	if key == "" {
		return text
	}
	needle := key + "="
	for {
		i := strings.Index(text, needle)
		if i < 0 {
			return text
		}
		j := i + len(needle)
		for j < len(text) {
			switch text[j] {
			case '&', ' ', '"', '\'', '\n', '\r':
				goto done
			}
			j++
		}
	done:
		text = text[:i+len(needle)] + "[redacted]" + text[j:]
	}
}
