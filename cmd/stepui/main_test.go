// Package main tests verify that the production dependency-wiring helper
// buildDeps produces a fully populated app.Deps — every required field
// non-nil — and that app.NewHandler does not panic when given those deps.
//
// This is distinct from the handler-level tests in internal/app/server_test.go:
// those prove the emit-point writes audit rows through the test-harness Deps;
// this test proves production Deps completeness, so dropping any field (e.g.
// Audit) from buildDeps is caught here rather than at runtime.
package main

import (
	"testing"

	"github.com/nofuturekid/step-ui-ng/internal/app"
	"github.com/nofuturekid/step-ui-ng/internal/config"
	"github.com/nofuturekid/step-ui-ng/internal/crypto"
	"github.com/nofuturekid/step-ui-ng/internal/store"
)

func TestBuildDepsAllFieldsNonNil(t *testing.T) {
	dir := t.TempDir()

	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	box, err := crypto.NewBox(dir)
	if err != nil {
		t.Fatalf("crypto.NewBox: %v", err)
	}

	cfg := config.Config{
		Addr:             ":8080",
		DataDir:          dir,
		RenewDefaultDays: config.DefaultRenewDays,
	}

	deps := buildDeps(st, box, cfg)

	if deps.DB == nil {
		t.Error("buildDeps: DB is nil")
	}
	if deps.Users == nil {
		t.Error("buildDeps: Users is nil")
	}
	if deps.Settings == nil {
		t.Error("buildDeps: Settings is nil")
	}
	if deps.Certs == nil {
		t.Error("buildDeps: Certs is nil")
	}
	if deps.Audit == nil {
		t.Error("buildDeps: Audit is nil")
	}
	if deps.Sessions == nil {
		t.Error("buildDeps: Sessions is nil")
	}

	// app.NewHandler panics on the first nil dep; if buildDeps is correct it
	// must not panic.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("app.NewHandler panicked with complete buildDeps: %v", r)
		}
	}()
	app.NewHandler(deps)
}
