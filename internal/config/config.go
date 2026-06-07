// Package config loads the minimal runtime configuration.
//
// Almost everything (Step-CA connection, provisioners, ACME, users) is
// configured in the UI and stored in SQLite. Only a couple of operational
// knobs come from the environment.
package config

import (
	"flag"
	"os"
	"strconv"
	"strings"
)

// DefaultRenewDays is the fallback renew validity (in days) shown on the renew
// form when RENEW_DEFAULT_DAYS is unset or invalid. The default is configurable
// per spec/0008 (FR-2): it must not be hard-coded into the renew logic.
const DefaultRenewDays = 90

// Config holds the minimal process configuration.
type Config struct {
	// Addr is the listen address, e.g. ":8080".
	Addr string
	// DataDir holds the SQLite database and the master key file (secret.key).
	DataDir string
	// SecureCookies sets the Secure attribute on session and CSRF cookies.
	// Enable it (COOKIE_SECURE=1/true) when the UI is served over HTTPS;
	// defaults to false so plain-HTTP homelab setups still work.
	SecureCookies bool
	// RenewDefaultDays is the validity (in days) pre-filled on the renew form
	// (spec/0008 FR-2). Configurable via RENEW_DEFAULT_DAYS; defaults to
	// DefaultRenewDays. The provisioner's own max still bounds the actual renew.
	RenewDefaultDays int
}

// Load reads configuration from the environment, applying sensible defaults.
func Load() Config {
	return Config{
		Addr:             ":" + env("PORT", "8080"),
		DataDir:          env("DATA_DIR", "./data"),
		SecureCookies:    boolEnv("COOKIE_SECURE"),
		RenewDefaultDays: intEnv("RENEW_DEFAULT_DAYS", DefaultRenewDays),
	}
}

// LoadWithFlags layers command-line flags over the environment: it starts from
// Load() (the env-derived defaults) and lets explicitly-set flags override them.
// A LOCAL flag.FlagSet is used (no global state) so this is testable and never
// touches the process-wide CommandLine. Only flags the caller actually set take
// effect (via fs.Visit) — an unset flag leaves the env-derived value untouched,
// so the precedence is: flag > env > built-in default.
//
// Flags: -addr, -data-dir, -cookie-secure, -renew-default-days, and -version
// (which sets the returned showVersion=true so the caller can print and exit
// before opening any store). A parse error (including -h/-help) is returned.
func LoadWithFlags(args []string) (cfg Config, showVersion bool, err error) {
	cfg = Load()

	fs := flag.NewFlagSet("stepui", flag.ContinueOnError)
	addr := fs.String("addr", cfg.Addr, "listen address, e.g. :8080 (overrides PORT)")
	dataDir := fs.String("data-dir", cfg.DataDir, "data directory for the SQLite DB and master key (overrides DATA_DIR)")
	cookieSecure := fs.Bool("cookie-secure", cfg.SecureCookies, "set the Secure attribute on cookies; enable behind HTTPS (overrides COOKIE_SECURE)")
	renewDays := fs.Int("renew-default-days", cfg.RenewDefaultDays, "default renew validity in days (overrides RENEW_DEFAULT_DAYS)")
	version := fs.Bool("version", false, "print version and exit")

	if err = fs.Parse(args); err != nil {
		return Config{}, false, err
	}

	// Only override fields whose flag was explicitly set, so the env-derived
	// defaults survive when a flag is absent (flag > env precedence).
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "addr":
			cfg.Addr = *addr
		case "data-dir":
			cfg.DataDir = *dataDir
		case "cookie-secure":
			cfg.SecureCookies = *cookieSecure
		case "renew-default-days":
			cfg.RenewDefaultDays = *renewDays
		}
	})

	return cfg, *version, nil
}

// intEnv reads key as a positive integer, falling back to def when unset,
// non-numeric, or not positive.
func intEnv(key string, def int) int {
	if n, err := strconv.Atoi(os.Getenv(key)); err == nil && n > 0 {
		return n
	}
	return def
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// boolEnv reports whether key is set to a truthy value ("1" or "true",
// case-insensitive); anything else (including unset) is false.
func boolEnv(key string) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "1", "true":
		return true
	default:
		return false
	}
}
