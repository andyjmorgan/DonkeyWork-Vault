package httpapi

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"donkeywork.dev/vault-server/internal/audit"
	"donkeywork.dev/vault-server/internal/manifests"
	"donkeywork.dev/vault-server/internal/service"
)

// OIDCConfig configures interactive (human) JWT auth. Empty Authority disables JWT (access keys only).
// Web vs CLI client ids let the scope mapper grant different scopes per requesting OAuth client.
type OIDCConfig struct {
	Authority         string
	InternalAuthority string
	Audience          string
	ClientID          string // legacy web client id
	Scopes            string // legacy web scopes
	WebClientID       string
	CliClientID       string
	WebScopes         string
	CliScopes         string
	RequireHTTPS      bool
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func (o OIDCConfig) effectiveWebClientID() string {
	return firstNonEmpty(o.WebClientID, o.ClientID, o.Audience)
}
func (o OIDCConfig) effectiveCliClientID() string {
	return firstNonEmpty(o.CliClientID, "donkeywork-vault-cli")
}
func (o OIDCConfig) effectiveWebScopes() string {
	return firstNonEmpty(o.WebScopes, o.Scopes, "openid profile email")
}
func (o OIDCConfig) effectiveCliScopes() string {
	return firstNonEmpty(o.CliScopes, "openid profile email offline_access")
}

// Deps are the constructed dependencies the server needs.
type Deps struct {
	APIKeys      *service.APIKeyService
	AccessKeys   *service.AccessKeyService
	OAuthConfigs *service.OAuthConfigService
	OAuthTokens  *service.OAuthTokenService
	OAuthFlow    *service.OAuthFlowService
	Resolver     *manifests.Resolver
	Discovery    *manifests.Discovery
	AuditLog     *audit.Log
	AuditQuery   *audit.QueryService
	IPResolver   *audit.ForwardedIPResolver
	Logger       *slog.Logger

	OIDC          OIDCConfig
	PublicBaseURL string
}

// Server holds the transport dependencies and renders the HTTP handler.
type Server struct {
	deps        Deps
	verifier    atomic.Pointer[oidc.IDTokenVerifier]
	authOn      bool
	appConfig   appConfigResponse
	webClientID string
	cliClientID string
	logger      *slog.Logger
	rate        *ipRateLimiter
}

// jwtVerifier returns the OIDC verifier, or nil while IdP discovery has not yet succeeded.
func (s *Server) jwtVerifier() *oidc.IDTokenVerifier {
	return s.verifier.Load()
}

// NewServer builds the server. When OIDC is configured it discovers the provider and builds a JWT
// verifier. IdP discovery failure at startup is NOT fatal: access-key callers don't need the IdP,
// so the server starts and keeps retrying discovery in the background; JWT requests get 503 until
// it succeeds. Config errors (non-HTTPS authority with RequireHTTPS) fail fast.
func NewServer(ctx context.Context, deps Deps) (*Server, error) {
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{deps: deps, logger: logger, rate: newIPRateLimiter(rateLimitPerWindow, rateLimitWindow)}

	s.webClientID = deps.OIDC.effectiveWebClientID()
	s.cliClientID = deps.OIDC.effectiveCliClientID()
	s.authOn = deps.OIDC.Authority != ""
	s.appConfig = appConfigResponse{
		Authority:            deps.OIDC.Authority,
		ClientID:             s.webClientID,
		Scopes:               deps.OIDC.effectiveWebScopes(),
		AuthEnabled:          s.authOn,
		CliClientID:          s.cliClientID,
		CliScopes:            deps.OIDC.effectiveCliScopes(),
		RequireHTTPSMetadata: deps.OIDC.RequireHTTPS,
	}

	if s.authOn {
		// When RequireHTTPS is set, refuse to fetch IdP metadata over plain http (a forged
		// discovery/JWKS document would mint arbitrary identities).
		if deps.OIDC.RequireHTTPS {
			for _, u := range []string{deps.OIDC.Authority, deps.OIDC.InternalAuthority} {
				if u != "" && !strings.HasPrefix(strings.ToLower(u), "https://") {
					return nil, fmt.Errorf("OIDC authority %q is not https and VAULT_OIDC_REQUIRE_HTTPS is true", u)
				}
			}
		}
		if err := s.initVerifier(ctx); err != nil {
			s.logger.Warn("oidc discovery failed; JWT auth unavailable until the IdP is reachable (access keys unaffected)", "err", err)
			go s.retryVerifier(ctx)
		}
	}

	return s, nil
}

// initVerifier performs OIDC discovery once and installs the JWT verifier.
func (s *Server) initVerifier(ctx context.Context) error {
	issuerCtx := ctx
	// Allow a separate in-cluster metadata URL while still validating the public issuer.
	if s.deps.OIDC.InternalAuthority != "" && s.deps.OIDC.InternalAuthority != s.deps.OIDC.Authority {
		issuerCtx = oidc.InsecureIssuerURLContext(ctx, s.deps.OIDC.Authority)
	}
	authority := s.deps.OIDC.Authority
	if s.deps.OIDC.InternalAuthority != "" {
		authority = s.deps.OIDC.InternalAuthority
	}
	provider, err := oidc.NewProvider(issuerCtx, authority)
	if err != nil {
		return err
	}
	// Audience varies by IdP (often in azp), so skip the client-id check — the issuer + signature
	// are the trust anchors.
	s.verifier.Store(provider.Verifier(&oidc.Config{SkipClientIDCheck: true}))
	return nil
}

// retryVerifier keeps attempting IdP discovery with capped backoff until it succeeds or ctx ends.
func (s *Server) retryVerifier(ctx context.Context) {
	backoff := 5 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if err := s.initVerifier(ctx); err != nil {
			s.logger.Warn("oidc discovery retry failed", "err", err)
			if backoff < 2*time.Minute {
				backoff *= 2
			}
			continue
		}
		s.logger.Info("oidc discovery succeeded; JWT auth enabled")
		return
	}
}
