// Package config loads the minimal runtime configuration.
//
// Almost everything (Step-CA connection, provisioners, ACME, users) is
// configured in the UI and stored in SQLite. Only a couple of operational
// knobs come from the environment.
package config

import (
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
