package config

import (
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("PORT", "")
	t.Setenv("DATA_DIR", "")
	t.Setenv("COOKIE_SECURE", "")
	t.Setenv("RENEW_DEFAULT_DAYS", "")
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
	if cfg.RenewDefaultDays != DefaultRenewDays {
		t.Fatalf("RenewDefaultDays = %d, want %d (the configurable default, not hard-coded)",
			cfg.RenewDefaultDays, DefaultRenewDays)
	}
}

// TestRenewDefaultDaysFromEnv proves the renew default is CONFIGURABLE (spec/0008
// FR-2): a valid RENEW_DEFAULT_DAYS overrides the built-in default, and an
// invalid/zero/negative value falls back to it (never hard-coded to 90 elsewhere).
func TestRenewDefaultDaysFromEnv(t *testing.T) {
	for _, tc := range []struct {
		val  string
		want int
	}{
		{"30", 30},
		{"365", 365},
		{"", DefaultRenewDays},
		{"0", DefaultRenewDays},
		{"-5", DefaultRenewDays},
		{"notanumber", DefaultRenewDays},
	} {
		t.Run(tc.val, func(t *testing.T) {
			t.Setenv("RENEW_DEFAULT_DAYS", tc.val)
			if got := Load().RenewDefaultDays; got != tc.want {
				t.Fatalf("RENEW_DEFAULT_DAYS=%q → RenewDefaultDays=%d, want %d", tc.val, got, tc.want)
			}
		})
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
