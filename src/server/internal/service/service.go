// Package service holds the vault's domain logic: API keys, access keys, OAuth provider configs,
// OAuth tokens and the OAuth authorization flow. Each service depends on the store.Store interface,
// the envelope cipher and the audit sink, so it can be unit-tested with fakes. Every public method
// opens a detailed span (traces pillar) and the services emit audit events that also drive metrics.
package service

import (
	"context"
	"encoding/base64"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	"donkeywork.dev/vault-server/internal/contracts"
)

// tracer is the shared service tracer; spans are named "<entity>.<operation>".
var tracer = otel.Tracer("donkeywork.dev/vault-server/service")

// startSpan opens a child span and returns the derived context and the span.
func startSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	return tracer.Start(ctx, name)
}

// ValidationError is returned for invalid create/edit input; the transport maps it to HTTP 400.
type ValidationError struct{ Message string }

func (e ValidationError) Error() string { return e.Message }

// OAuthAuthorizationError is returned when an OAuth begin/complete fails; mapped to HTTP 400.
type OAuthAuthorizationError struct{ Message string }

func (e OAuthAuthorizationError) Error() string { return e.Message }

// OAuthRefreshError is returned when a token refresh fails; mapped to HTTP 502.
type OAuthRefreshError struct{ Message string }

func (e OAuthRefreshError) Error() string { return e.Message }

// CredentialUsage is the single source of truth for how a stored credential is presented: the kind
// discriminator decides the scheme — http_basic emits an Authorization: Basic header, every other
// kind sends the secret behind header/prefix (or, for login kinds like ssh, carries no HTTP header).
type CredentialUsage struct{}

const (
	schemeBasic  = "basic"
	schemeHeader = "header"
)

// Scheme returns the auth scheme implied by the credential kind. Only http_basic assembles a Basic
// Authorization header; every other kind (including username-bearing ssh/username_password) sends
// the secret behind header/prefix.
func Scheme(kind contracts.CredentialKind) string {
	if kind == contracts.KindHTTPBasic {
		return schemeBasic
	}
	return schemeHeader
}

// HeaderName returns the effective header name, defaulting to Authorization.
func HeaderName(header string) string {
	if header == "" {
		return "Authorization"
	}
	return header
}

// AssembleHeader builds the ready-to-send HTTP header for a credential. For http_basic it emits
// Authorization: Basic base64(username:secret); every other kind emits {header}: {prefix}{secret}.
func AssembleHeader(kind contracts.CredentialKind, header, prefix, username, secret string) (name, value string) {
	if kind == contracts.KindHTTPBasic {
		token := base64.StdEncoding.EncodeToString([]byte(username + ":" + secret))
		return HeaderName(header), "Basic " + token
	}
	return HeaderName(header), prefix + secret
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func ptrIfNotEmpty(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return &s
}
