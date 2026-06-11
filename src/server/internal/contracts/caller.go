// Package contracts holds the cross-cutting types shared by the transport, service and store
// layers: the ambient caller identity, the credential-kind discriminator and the audit event model.
//
// Where the original C# used AsyncLocal-backed ambient accessors (IVaultCallerContext,
// IAuditContextAccessor), the Go port threads the same data through context.Context. This is the
// idiomatic equivalent, it is explicit rather than magical, and it flows naturally alongside the
// OpenTelemetry span context so every log line and DB span can be correlated to the caller.
package contracts

import (
	"context"

	"github.com/google/uuid"
)

// Caller is the resolved identity for a request. TenantID is carried but not enforced
// (single-tenant for now); UserID drives row scoping in the store layer.
type Caller struct {
	UserID   uuid.UUID
	TenantID uuid.UUID
}

type callerKey struct{}

// WithCaller returns a context carrying the caller identity.
func WithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// CallerFrom returns the caller identity from the context, or a zero Caller when none is set
// (e.g. background work or the anonymous OAuth callback, which supplies the owner explicitly).
func CallerFrom(ctx context.Context) Caller {
	if c, ok := ctx.Value(callerKey{}).(Caller); ok {
		return c
	}
	return Caller{}
}
