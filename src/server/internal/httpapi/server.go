package httpapi

import (
	"context"
	"log/slog"

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
	verifier    *oidc.IDTokenVerifier
	authOn      bool
	appConfig   appConfigResponse
	webClientID string
	cliClientID string
	logger      *slog.Logger
}

// NewServer builds the server. When OIDC is configured it discovers the provider and builds a JWT
// verifier; failure to reach the IdP at startup is fatal only when auth is required.
func NewServer(ctx context.Context, deps Deps) (*Server, error) {
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{deps: deps, logger: logger}

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
		issuerCtx := ctx
		// Allow a separate in-cluster metadata URL while still validating the public issuer.
		if deps.OIDC.InternalAuthority != "" && deps.OIDC.InternalAuthority != deps.OIDC.Authority {
			issuerCtx = oidc.InsecureIssuerURLContext(ctx, deps.OIDC.Authority)
		}
		authority := deps.OIDC.Authority
		if deps.OIDC.InternalAuthority != "" {
			authority = deps.OIDC.InternalAuthority
		}
		provider, err := oidc.NewProvider(issuerCtx, authority)
		if err != nil {
			return nil, err
		}
		// Audience varies by IdP (often in azp), so skip the client-id check — the issuer + signature
		// are the trust anchors, exactly as the C# config did (ValidateAudience = false).
		s.verifier = provider.Verifier(&oidc.Config{SkipClientIDCheck: true})
	}

	return s, nil
}
