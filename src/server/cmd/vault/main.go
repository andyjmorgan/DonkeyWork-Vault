// Command vault is the DonkeyWork Vault HTTP service: the REST API, OAuth flows and (optionally) the
// React SPA, backed by Postgres.
package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"donkeywork.dev/vault-server/internal/audit"
	"donkeywork.dev/vault-server/internal/config"
	"donkeywork.dev/vault-server/internal/crypto"
	"donkeywork.dev/vault-server/internal/db"
	"donkeywork.dev/vault-server/internal/httpapi"
	"donkeywork.dev/vault-server/internal/httpx"
	"donkeywork.dev/vault-server/internal/manifests"
	"donkeywork.dev/vault-server/internal/service"
	"donkeywork.dev/vault-server/internal/store"
	"donkeywork.dev/vault-server/internal/telemetry"
)

func main() {
	if err := run(); err != nil {
		// telemetry may not be up yet; stderr is always safe.
		println("fatal:", err.Error())
		os.Exit(1)
	}
}

func run() error {
	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	tel, err := telemetry.Setup(rootCtx, telemetry.Config{
		OTLPEndpoint: cfg.OTLPEndpoint, Insecure: cfg.OTLPInsecure,
		ServiceVersion: cfg.ServiceVersion, Environment: cfg.Environment,
	})
	if err != nil {
		return err
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tel.Shutdown(shutdownCtx)
	}()
	logger := tel.Logger

	metrics, err := telemetry.NewMetrics()
	if err != nil {
		return err
	}

	pg, err := store.NewPostgres(rootCtx, cfg.DSN)
	if err != nil {
		return err
	}
	defer pg.Close()

	if cfg.RunMigrations {
		logger.Info("applying database migrations")
		if err := db.Migrate(rootCtx, pg.Pool()); err != nil {
			return err
		}
	}

	kek, err := crypto.NewLocalKekProvider(cfg.ActiveKekID, cfg.Keks)
	if err != nil {
		return err
	}
	cipher := crypto.NewEnvelopeCipher(kek)

	loader, err := manifests.NewLoader()
	if err != nil {
		return err
	}
	resolver := manifests.NewResolver(pg, loader)

	auditLog := audit.NewLog(cfg.AuditChannelCap, logger, metrics)
	writer := audit.NewWriter(auditLog, pg, logger, metrics, audit.WriterOptions{BatchSize: cfg.AuditBatchSize, FlushInterval: cfg.AuditFlushInterval})
	retention := audit.NewRetention(pg, logger, audit.RetentionOptions{RetentionDays: cfg.AuditRetentionDays, SweepInterval: cfg.AuditSweepInterval, BatchSize: cfg.AuditRetentionBatch})
	oauthStateSweeper := service.NewOAuthStateSweeper(pg, logger, 0)
	auditQuery := audit.NewQueryService(pg, auditLog)

	// Outbound HTTP for OAuth/discovery, traced via otelhttp so exchanges are child spans. The
	// transport blocks link-local/metadata destinations (SSRF guard for user-stored endpoints).
	oauthClient := &http.Client{Timeout: 30 * time.Second, Transport: otelhttp.NewTransport(httpx.DefaultSafeTransport())}

	deps := httpapi.Deps{
		APIKeys:      service.NewAPIKeyService(pg, cipher, auditLog),
		AccessKeys:   service.NewAccessKeyService(pg, auditLog),
		OAuthConfigs: service.NewOAuthConfigService(pg, cipher, auditLog, resolver),
		OAuthTokens:  service.NewOAuthTokenService(pg, cipher, auditLog, resolver, oauthClient),
		OAuthFlow:    service.NewOAuthFlowService(pg, cipher, resolver, auditLog, oauthClient, logger),
		Resolver:     resolver,
		Discovery:    manifests.NewDiscovery(oauthClient),
		AuditLog:     auditLog,
		AuditQuery:   auditQuery,
		IPResolver:   audit.NewForwardedIPResolver(cfg.TrustedProxies),
		Logger:       logger,
		OIDC: httpapi.OIDCConfig{
			Authority: cfg.OIDCAuthority, InternalAuthority: cfg.OIDCInternal, Audience: cfg.OIDCAudience,
			ClientID: cfg.OIDCClientID, Scopes: cfg.OIDCScopes,
			WebClientID: cfg.OIDCWebClientID, CliClientID: cfg.OIDCCliClientID,
			WebScopes: cfg.OIDCWebScopes, CliScopes: cfg.OIDCCliScopes,
			RequireHTTPS: cfg.OIDCRequireHTTPS,
		},
		PublicBaseURL: cfg.PublicBaseURL,
	}

	srv, err := httpapi.NewServer(rootCtx, deps)
	if err != nil {
		return err
	}

	handler := srv.Handler()
	if cfg.WebRoot != "" {
		handler = withStaticFallback(handler, cfg.WebRoot)
	}

	// Background workers.
	var wg sync.WaitGroup
	workerCtx, cancelWorkers := context.WithCancel(context.Background())
	wg.Add(3)
	go func() { defer wg.Done(); writer.Run(workerCtx) }()
	go func() { defer wg.Done(); retention.Run(workerCtx) }()
	go func() { defer wg.Done(); oauthStateSweeper.Run(workerCtx) }()

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("vault listening", "addr", cfg.ListenAddr, "auth_enabled", cfg.OIDCAuthority != "")
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	var runErr error
	select {
	case <-rootCtx.Done():
		logger.Info("shutdown signal received")
	case runErr = <-serveErr:
		logger.Error("http server failed", "err", runErr)
	}

	// Graceful shutdown (both paths): stop the server, then drain audit (close channel, wait for
	// the writer) so queued events are flushed even when the listener died.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)

	auditLog.Complete()
	cancelWorkers()
	wg.Wait()
	return runErr
}

// withStaticFallback serves the SPA from webRoot for non-API routes, falling back to index.html so
// client-side routing works. /api and /healthz pass through to the API handler.
func withStaticFallback(api http.Handler, webRoot string) http.Handler {
	fs := http.FileServer(http.Dir(webRoot))
	index := filepath.Join(webRoot, "index.html")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api") || r.URL.Path == "/healthz" {
			api.ServeHTTP(w, r)
			return
		}
		if path := filepath.Join(webRoot, filepath.Clean(r.URL.Path)); fileExists(path) {
			fs.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, index)
	})
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
