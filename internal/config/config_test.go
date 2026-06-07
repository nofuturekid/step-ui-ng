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

// --- LoadWithFlags: flags layer over env ------------------------------------

// Flags must override the env-derived defaults: precedence is flag > env.
func TestLoadWithFlagsOverridesEnv(t *testing.T) {
	t.Setenv("PORT", "9000")
	t.Setenv("DATA_DIR", "/env-data")
	t.Setenv("COOKIE_SECURE", "true")
	t.Setenv("RENEW_DEFAULT_DAYS", "30")

	cfg, showVersion, err := LoadWithFlags([]string{
		"-addr", ":7777",
		"-data-dir", "/flag-data",
		"-cookie-secure=false",
		"-renew-default-days", "120",
	})
	if err != nil {
		t.Fatalf("LoadWithFlags: %v", err)
	}
	if showVersion {
		t.Fatal("showVersion = true, want false (no -version)")
	}
	if cfg.Addr != ":7777" {
		t.Fatalf("Addr = %q, want :7777 (flag overrides PORT)", cfg.Addr)
	}
	if cfg.DataDir != "/flag-data" {
		t.Fatalf("DataDir = %q, want /flag-data (flag overrides DATA_DIR)", cfg.DataDir)
	}
	if cfg.SecureCookies {
		t.Fatal("SecureCookies = true, want false (-cookie-secure=false overrides COOKIE_SECURE=true)")
	}
	if cfg.RenewDefaultDays != 120 {
		t.Fatalf("RenewDefaultDays = %d, want 120 (flag overrides RENEW_DEFAULT_DAYS)", cfg.RenewDefaultDays)
	}
}

// When a flag is absent, the env-derived value must be used (the flag default is
// the env value, and fs.Visit only fires for explicitly-set flags).
func TestLoadWithFlagsFallsBackToEnv(t *testing.T) {
	t.Setenv("PORT", "9000")
	t.Setenv("DATA_DIR", "/env-data")
	t.Setenv("COOKIE_SECURE", "true")
	t.Setenv("RENEW_DEFAULT_DAYS", "30")

	// Only -addr is set; the rest must come from the environment.
	cfg, _, err := LoadWithFlags([]string{"-addr", ":7777"})
	if err != nil {
		t.Fatalf("LoadWithFlags: %v", err)
	}
	if cfg.Addr != ":7777" {
		t.Fatalf("Addr = %q, want :7777 (set via flag)", cfg.Addr)
	}
	if cfg.DataDir != "/env-data" {
		t.Fatalf("DataDir = %q, want /env-data (from env, flag absent)", cfg.DataDir)
	}
	if !cfg.SecureCookies {
		t.Fatal("SecureCookies = false, want true (from env, flag absent)")
	}
	if cfg.RenewDefaultDays != 30 {
		t.Fatalf("RenewDefaultDays = %d, want 30 (from env, flag absent)", cfg.RenewDefaultDays)
	}
}

// With neither flag nor env, the built-in defaults apply (mirrors Load()).
func TestLoadWithFlagsDefaults(t *testing.T) {
	t.Setenv("PORT", "")
	t.Setenv("DATA_DIR", "")
	t.Setenv("COOKIE_SECURE", "")
	t.Setenv("RENEW_DEFAULT_DAYS", "")

	cfg, showVersion, err := LoadWithFlags(nil)
	if err != nil {
		t.Fatalf("LoadWithFlags: %v", err)
	}
	if showVersion {
		t.Fatal("showVersion = true, want false")
	}
	if cfg.Addr != ":8080" {
		t.Fatalf("Addr = %q, want :8080", cfg.Addr)
	}
	if cfg.DataDir != "./data" {
		t.Fatalf("DataDir = %q, want ./data", cfg.DataDir)
	}
	if cfg.SecureCookies {
		t.Fatal("SecureCookies = true, want false by default")
	}
	if cfg.RenewDefaultDays != DefaultRenewDays {
		t.Fatalf("RenewDefaultDays = %d, want %d", cfg.RenewDefaultDays, DefaultRenewDays)
	}
}

// -version sets the returned showVersion so the caller can print and exit before
// any side effects (opening the store / creating the master key).
func TestLoadWithFlagsVersion(t *testing.T) {
	_, showVersion, err := LoadWithFlags([]string{"-version"})
	if err != nil {
		t.Fatalf("LoadWithFlags: %v", err)
	}
	if !showVersion {
		t.Fatal("showVersion = false, want true for -version")
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
