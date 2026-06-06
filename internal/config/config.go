// Package config loads the minimal runtime configuration.
//
// Almost everything (Step-CA connection, provisioners, ACME, users) is
// configured in the UI and stored in SQLite. Only a couple of operational
// knobs come from the environment.
package config

import "os"

// Config holds the minimal process configuration.
type Config struct {
	// Addr is the listen address, e.g. ":8080".
	Addr string
	// DataDir holds the SQLite database and the master key file (secret.key).
	DataDir string
}

// Load reads configuration from the environment, applying sensible defaults.
func Load() Config {
	return Config{
		Addr:    ":" + env("PORT", "8080"),
		DataDir: env("DATA_DIR", "./data"),
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
