// Package audit is the append-only audit trail: a fire-and-forget bounded-channel sink, a background
// batch writer, a retention sweeper, header redaction, a trusted-proxy IP resolver and a caller-scoped
// query service. It is a faithful port of the C# audit subsystem; auditing must never block or fail
// the credential path, and no record ever carries secret material.
package audit

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// EventType is the kind of credential-sensitive event recorded. Values are stable and stored as int;
// they must not be reordered (they match the C# AuditEventType).
type EventType int

const (
	EventUnknown           EventType = 0
	EventTokenAccessed     EventType = 1
	EventTokenRefreshed    EventType = 2
	EventTokenAdded        EventType = 3
	EventCredentialCreated EventType = 4
	EventAuthSucceeded     EventType = 5
	EventAuthFailed        EventType = 6
	EventAuditAccessed     EventType = 7
	EventTokenRemoved      EventType = 8
)

// String renders the PascalCase name the .NET service emitted on the wire (enum.ToString()), so the
// audit DTO's `type` field is unchanged for existing API consumers.
func (t EventType) String() string {
	switch t {
	case EventTokenAccessed:
		return "TokenAccessed"
	case EventTokenRefreshed:
		return "TokenRefreshed"
	case EventTokenAdded:
		return "TokenAdded"
	case EventCredentialCreated:
		return "CredentialCreated"
	case EventAuthSucceeded:
		return "AuthSucceeded"
	case EventAuthFailed:
		return "AuthFailed"
	case EventAuditAccessed:
		return "AuditAccessed"
	case EventTokenRemoved:
		return "TokenRemoved"
	default:
		return "Unknown"
	}
}

// ParseEventType maps a case-insensitive name to an EventType; ok is false for an unknown name.
func ParseEventType(s string) (EventType, bool) {
	for t := EventUnknown; t <= EventTokenRemoved; t++ {
		if equalFold(t.String(), s) {
			return t, true
		}
	}
	return EventUnknown, false
}

// Outcome is whether the audited operation succeeded.
type Outcome int

const (
	OutcomeSuccess Outcome = 0
	OutcomeFailure Outcome = 1
)

// String renders "Success"/"Failure" to match the .NET wire form.
func (o Outcome) String() string {
	if o == OutcomeFailure {
		return "Failure"
	}
	return "Success"
}

// ParseOutcome maps a case-insensitive name to an Outcome.
func ParseOutcome(s string) (Outcome, bool) {
	switch {
	case equalFold(s, "Success"):
		return OutcomeSuccess, true
	case equalFold(s, "Failure"):
		return OutcomeFailure, true
	default:
		return OutcomeSuccess, false
	}
}

// Event is an immutable audit record. It carries no secret material.
type Event struct {
	Type            EventType
	Outcome         Outcome
	UserID          uuid.UUID
	TenantID        uuid.UUID
	AccessKeyID     *uuid.UUID
	AccessKeyPrefix *string
	AccessKeyName   *string
	SourceIP        *string
	Headers         map[string]string
	TargetKind      *string
	TargetProvider  *string
	TargetAccount   *string
	TargetName      *string
	Transport       string
	Method          *string
	Detail          *string
	CreatedAt       time.Time
}

// RequestInfo is the per-request audit metadata resolved by the transport and read by the emitter.
type RequestInfo struct {
	SourceIP        *string
	Headers         map[string]string
	AccessKeyID     *uuid.UUID
	AccessKeyPrefix *string
	AccessKeyName   *string
	Transport       string
	Method          *string
}

type reqInfoKey struct{}

// WithRequestInfo attaches per-request audit metadata to the context.
func WithRequestInfo(ctx context.Context, info RequestInfo) context.Context {
	return context.WithValue(ctx, reqInfoKey{}, info)
}

// RequestInfoFrom reads the per-request audit metadata, defaulting to an empty "http"/"unknown" set.
func RequestInfoFrom(ctx context.Context) RequestInfo {
	if i, ok := ctx.Value(reqInfoKey{}).(RequestInfo); ok {
		return i
	}
	return RequestInfo{Transport: "unknown", Headers: map[string]string{}}
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
