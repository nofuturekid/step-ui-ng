package config

import (
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("PORT", "")
	t.Setenv("DATA_DIR", "")
	t.Setenv("COOKIE_SECURE", "")
	cfg := Load()
	if cfg.Addr != ":8080" {
		t.Fatalf("Addr = %q, want :8080", cfg.Addr)
	}
	if cfg.DataDir != "./data" {
		t.Fatalf("DataDir = %q, want ./data", cfg.DataDir)
	}
	if cfg.SecureCookies {
		t.Fatalf("SecureCookies = true, want false by default")
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("PORT", "9000")
	t.Setenv("DATA_DIR", "/data")
	t.Setenv("COOKIE_SECURE", "true")
	cfg := Load()
	if cfg.Addr != ":9000" {
		t.Fatalf("Addr = %q, want :9000", cfg.Addr)
	}
	if cfg.DataDir != "/data" {
		t.Fatalf("DataDir = %q, want /data", cfg.DataDir)
	}
	if !cfg.SecureCookies {
		t.Fatalf("SecureCookies = false, want true when COOKIE_SECURE=true")
	}
}

func TestSecureCookiesOverrides(t *testing.T) {
	for _, tc := range []struct {
		val  string
		want bool
	}{
		{"1", true},
		{"true", true},
		{"TRUE", true},
		{"0", false},
		{"false", false},
		{"", false},
		{"yes", false},
	} {
		t.Run(tc.val, func(t *testing.T) {
			t.Setenv("COOKIE_SECURE", tc.val)
			if got := Load().SecureCookies; got != tc.want {
				t.Fatalf("COOKIE_SECURE=%q → SecureCookies=%v, want %v", tc.val, got, tc.want)
			}
		})
	}
}
