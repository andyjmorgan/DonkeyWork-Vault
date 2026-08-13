package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// Handler builds the full HTTP handler: the API surface plus health, wrapped in otelhttp so every
// request is the root span of a trace (the traces pillar's entry point). A static file handler for
// the SPA can be layered by the caller via Fallback.
func (s *Server) Handler() http.Handler {
	return otelhttp.NewHandler(s.router(), "vault.http")
}

// router builds the bare chi mux — separate from Handler so tests can walk the route table.
func (s *Server) router() chi.Router {
	r := chi.NewRouter()

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	r.Group(func(r chi.Router) {
		r.Use(s.limits)
		r.Use(s.baseContext)

		// Anonymous endpoints.
		r.Get("/api/config", s.handleConfig)
		r.Get("/api/oauth/callback", s.handleOAuthCallback)

		// Authenticated API surface.
		r.Route("/api/v1", func(r chi.Router) {
			r.Use(s.authenticate)

			r.Group(func(r chi.Router) {
				r.Use(s.scopeGate(""))

				r.Get("/me", s.handleMe)

				r.Get("/api-keys", s.handleListAPIKeys)
				r.Post("/api-keys", s.handleCreateAPIKey)
				r.Delete("/api-keys/{id}", s.handleDeleteAPIKey)
				r.Get("/api-keys/{name}/reveal", s.handleRevealAPIKey)

				r.Get("/credentials/{name}", s.handleCredentialShape)

				r.Get("/access-keys", s.handleListAccessKeys)
				r.Post("/access-keys", s.handleCreateAccessKey)
				r.Patch("/access-keys/{id}", s.handleSetAccessKeyEnabled)
				r.Delete("/access-keys/{id}", s.handleDeleteAccessKey)

				r.Get("/manifests", s.handleListManifests)
				r.Get("/manifests/templates", s.handleListTemplates)
				r.Post("/manifests/oauth", s.handleUpsertManifest)
				r.Post("/manifests/oauth/discover", s.handleDiscover)
				r.Delete("/manifests/{kind}/{key}", s.handleDeleteManifest)

				r.Get("/oauth/configs", s.handleListConfigs)
				r.Post("/oauth/configs", s.handleUpsertConfig)
				r.Delete("/oauth/configs/{id}", s.handleDeleteConfig)

				r.Get("/oauth/tokens", s.handleListTokens)
				r.Delete("/oauth/tokens/{id}", s.handleDeleteToken)
				r.Get("/oauth/{provider}/token", s.handleGetToken)
				r.Get("/oauth/{provider}/connect", s.handleConnect)
			})

			r.Group(func(r chi.Router) {
				r.Use(s.scopeGate("vault:audit"))
				r.Get("/audit", s.handleAudit)
			})
		})
	})

	return r
}
