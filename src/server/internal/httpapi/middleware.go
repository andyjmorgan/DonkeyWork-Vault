package httpapi

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/audit"
	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/service"
)

// apiKeyPrefix marks an access-key secret presented as X-Api-Key or Authorization: Bearer.
const apiKeyPrefix = "dwv_"

type scopesKey struct{}

func scopesFrom(ctx context.Context) map[string]bool {
	if s, ok := ctx.Value(scopesKey{}).(map[string]bool); ok {
		return s
	}
	return nil
}

// baseContext resolves the client IP and redacted headers and publishes the per-request audit
// metadata, so even anonymous endpoints (the OAuth callback) record IP + headers. The caller and the
// access-key reference are added later by authenticate.
func (s *Server) baseContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := audit.RequestInfo{
			SourceIP:  s.resolveIP(r),
			Headers:   audit.RedactHeaders(r.Header),
			Transport: "http",
			Method:    strPtr(r.Method + " " + r.URL.Path),
		}
		ctx := audit.WithRequestInfo(r.Context(), info)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authenticate resolves a presented credential (access key first, then OIDC JWT) and publishes the
// caller identity, scopes and (for access keys) the audit key reference. Auth outcomes are audited.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if secret := extractAccessKey(r); secret != "" {
			principal, err := s.deps.AccessKeys.Authenticate(ctx, secret)
			if err != nil || principal == nil {
				s.emitAuthFailed(ctx, "invalid or disabled API key.")
				writeError(w, http.StatusUnauthorized, "invalid or disabled API key.")
				return
			}
			ctx = s.withAccessKeyCaller(ctx, principal)
			s.deps.AuditLog.Emit(ctx, audit.EmitParams{Type: audit.EventAuthSucceeded, Outcome: audit.OutcomeSuccess,
				TargetKind: "access_key", TargetName: principal.Name})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		if raw := bearerToken(r); raw != "" && s.authOn {
			if s.jwtVerifier() == nil {
				// IdP discovery hasn't succeeded yet (it retries in the background).
				writeError(w, http.StatusServiceUnavailable, "identity provider unavailable; try again shortly.")
				return
			}
			ctx2, ok := s.authenticateJWT(ctx, w, raw)
			if !ok {
				return
			}
			next.ServeHTTP(w, r.WithContext(ctx2))
			return
		}

		s.emitAuthFailed(ctx, "no credential presented.")
		writeError(w, http.StatusUnauthorized, "authentication required.")
	})
}

func (s *Server) authenticateJWT(ctx context.Context, w http.ResponseWriter, raw string) (context.Context, bool) {
	idToken, err := s.jwtVerifier().Verify(ctx, raw)
	if err != nil {
		s.emitAuthFailed(ctx, "invalid bearer token.")
		writeError(w, http.StatusUnauthorized, "invalid bearer token.")
		return ctx, false
	}
	var claims struct {
		Sub               string `json:"sub"`
		TenantID          string `json:"tenant_id"`
		Email             string `json:"email"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		Azp               string `json:"azp"`
		ClientID          string `json:"client_id"`
	}
	if err := idToken.Claims(&claims); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid token claims.")
		return ctx, false //coverage:ignore OIDC lib already unmarshalled these bytes during Verify; decode cannot fail here
	}
	userID, err := uuid.Parse(claims.Sub)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authenticated subject is missing or not a valid identifier.")
		return ctx, false
	}
	tenantID, _ := uuid.Parse(claims.TenantID)

	ctx = contracts.WithCaller(ctx, contracts.Caller{UserID: userID, TenantID: tenantID})
	name := claims.Name
	if name == "" {
		name = claims.PreferredUsername
	}
	ctx = withIdentity(ctx, meIdentity{Email: emptyToNil(claims.Email), Name: emptyToNil(name)})

	// Scopes depend on the requesting OAuth client (web vs CLI).
	clientID := clientIDFromClaims(claims.Azp, claims.ClientID, idToken.Audience)
	granted := map[string]bool{}
	for _, sc := range vaultScopesFor(clientID, idToken.Audience, s.webClientID, s.cliClientID) {
		granted[sc] = true
	}
	ctx = context.WithValue(ctx, scopesKey{}, granted)
	return ctx, true
}

// withAccessKeyCaller sets the caller identity, scopes and audit key reference for an access key.
func (s *Server) withAccessKeyCaller(ctx context.Context, p *service.AccessKeyPrincipal) context.Context {
	ctx = contracts.WithCaller(ctx, contracts.Caller{UserID: p.UserID, TenantID: p.TenantID})

	granted := make(map[string]bool, len(p.Scopes))
	for _, sc := range p.Scopes {
		granted[sc] = true
	}
	ctx = context.WithValue(ctx, scopesKey{}, granted)

	// Augment the per-request audit metadata with the key reference (id/prefix/name, never secret).
	info := audit.RequestInfoFrom(ctx)
	id := p.ID
	info.AccessKeyID = &id
	info.AccessKeyPrefix = &p.KeyPrefix
	info.AccessKeyName = &p.Name
	return audit.WithRequestInfo(ctx, info)
}

// scopeGate enforces the required scope for the route. fixedScope pins a scope (e.g. vault:audit);
// otherwise GET/HEAD/OPTIONS need vault:read and mutations need vault:readwrite (which implies read).
func (s *Server) scopeGate(fixedScope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			required := fixedScope
			if required == "" {
				switch r.Method {
				case http.MethodGet, http.MethodHead, http.MethodOptions:
					required = "vault:read"
				default:
					required = "vault:readwrite"
				}
			}
			if !hasScope(scopesFrom(r.Context()), required) {
				s.emitScopeDenied(r.Context(), required)
				writeError(w, http.StatusForbidden, "caller missing required scope '"+required+"'.")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func hasScope(granted map[string]bool, required string) bool {
	if granted[required] {
		return true
	}
	// readwrite implies read (audit is standalone — not implied by readwrite).
	if strings.HasSuffix(required, ":read") {
		return granted[strings.TrimSuffix(required, ":read")+":readwrite"]
	}
	return false
}

func (s *Server) emitAuthFailed(ctx context.Context, reason string) {
	s.deps.AuditLog.Emit(ctx, audit.EmitParams{Type: audit.EventAuthFailed, Outcome: audit.OutcomeFailure, Detail: reason})
}

func (s *Server) emitScopeDenied(ctx context.Context, required string) {
	s.deps.AuditLog.Emit(ctx, audit.EmitParams{Type: audit.EventAuthFailed, Outcome: audit.OutcomeFailure,
		Detail: "missing scope '" + required + "'."})
}

func extractAccessKey(r *http.Request) string {
	if h := r.Header.Get("X-Api-Key"); strings.HasPrefix(h, apiKeyPrefix) {
		return h
	}
	if t := bearerToken(r); strings.HasPrefix(t, apiKeyPrefix) {
		return t
	}
	return ""
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	const bearer = "Bearer "
	if len(auth) > len(bearer) && strings.EqualFold(auth[:len(bearer)], bearer) {
		return strings.TrimSpace(auth[len(bearer):])
	}
	return ""
}

func (s *Server) resolveIP(r *http.Request) *string {
	peer := peerAddr(r.RemoteAddr)
	ip := s.deps.IPResolver.Resolve(peer, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"))
	if ip == "" {
		return nil
	}
	return &ip
}

func peerAddr(remoteAddr string) netip.Addr {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return a
	}
	return netip.Addr{}
}

func strPtr(s string) *string { return &s }

func emptyToNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
