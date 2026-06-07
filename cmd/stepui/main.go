// Command stepui is the entry point for the step-ui-ng server.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nofuturekid/step-ui-ng/internal/app"
	"github.com/nofuturekid/step-ui-ng/internal/audit"
	"github.com/nofuturekid/step-ui-ng/internal/certs"
	"github.com/nofuturekid/step-ui-ng/internal/config"
	"github.com/nofuturekid/step-ui-ng/internal/crypto"
	"github.com/nofuturekid/step-ui-ng/internal/settings"
	"github.com/nofuturekid/step-ui-ng/internal/store"
	"github.com/nofuturekid/step-ui-ng/internal/users"
)

// buildDeps constructs the production app.Deps from an open store, crypto box,
// and config. Extracted so that tests can verify every required field is wired
// without starting a full HTTP server.
func buildDeps(st *store.Store, box *crypto.Box, cfg config.Config) app.Deps {
	auditRec := audit.NewRecorder(st.DB())
	return app.Deps{
		DB:       st.DB(),
		Users:    users.NewRepo(st.DB()),
		Settings: settings.NewRepo(st.DB(), box),
		Certs:    certs.NewService(st.DB(), box, auditRec, certs.LiveSigner(), certs.LiveRevoker()),
		Audit:    auditRec,
		Sessions: app.NewSessionManager(st.DB(), cfg.SecureCookies),
		Config:   cfg,
	}
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg, showVersion, err := config.LoadWithFlags(os.Args[1:])
	if err != nil {
		slog.Error("parse flags", "err", err)
		os.Exit(2)
	}
	if showVersion {
		// Print the build version and exit before opening the store or creating
		// the master key, so `stepui -version` is a pure, side-effect-free query.
		os.Stdout.WriteString(app.BuildInfo() + "\n")
		os.Exit(0)
	}

	st, err := store.Open(cfg.DataDir)
	if err != nil {
		slog.Error("open store", "err", err)
		os.Exit(1)
	}
	defer func() { _ = st.Close() }()

	if v, err := st.Version(); err == nil {
		slog.Info("database ready", "schema_version", v)
	}

	// Ensure the master key exists (created on first start) so secrets can be
	// encrypted at rest, and keep the Box to seal CA admin secrets (spec/0004).
	box, err := crypto.NewBox(cfg.DataDir)
	if err != nil {
		slog.Error("init secrets encryption", "err", err)
		os.Exit(1)
	}
	slog.Info("secrets encryption ready")

	deps := buildDeps(st, box, cfg)

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           app.NewHandler(deps),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		slog.Info("starting server", "addr", cfg.Addr, "version", app.BuildInfo(), "data_dir", cfg.DataDir)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("graceful shutdown failed", "err", err)
	}
	slog.Info("server stopped")
}
