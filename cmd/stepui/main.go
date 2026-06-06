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

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg := config.Load()

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

	userRepo := users.NewRepo(st.DB())
	settingsRepo := settings.NewRepo(st.DB(), box)
	certsSvc := certs.NewService(st.DB(), box, audit.NewRecorder(st.DB()), certs.LiveSigner(), certs.LiveRevoker())
	sessions := app.NewSessionManager(st.DB(), cfg.SecureCookies)

	srv := &http.Server{
		Addr: cfg.Addr,
		Handler: app.NewHandler(app.Deps{
			DB:       st.DB(),
			Users:    userRepo,
			Settings: settingsRepo,
			Certs:    certsSvc,
			Sessions: sessions,
			Config:   cfg,
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		slog.Info("starting server", "addr", cfg.Addr, "version", app.Version, "data_dir", cfg.DataDir)
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
