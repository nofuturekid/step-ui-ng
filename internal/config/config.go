// Package config loads the minimal runtime configuration.
//
// Almost everything (Step-CA connection, provisioners, ACME, users) is
// configured in the UI and stored in SQLite. Only a couple of operational
// knobs come from the environment.
package config

import (
	"os"
	"strings"
)

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
}

// Load reads configuration from the environment, applying sensible defaults.
func Load() Config {
	return Config{
		Addr:          ":" + env("PORT", "8080"),
		DataDir:       env("DATA_DIR", "./data"),
		SecureCookies: boolEnv("COOKIE_SECURE"),
	}
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
