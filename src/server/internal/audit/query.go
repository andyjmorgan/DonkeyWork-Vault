package audit

import (
	"context"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/store"
)

// MaxLimit caps an audit page size.
const MaxLimit = 200

// Query is the caller-facing filter for reading the trail. Paging is clamped by the service.
type Query struct {
	Limit     int
	Offset    int
	Type      *EventType
	Outcome   *Outcome
	UserID    *uuid.UUID
	Since     *time.Time
	Until     *time.Time
}

// Result is a page of audit rows plus the total matching count.
type Result struct {
	Items  []store.AuditEntry
	Total  int
	Limit  int
	Offset int
}

// QueryService reads the append-only trail for the ambient caller. Reading the trail is itself
// audited (EventAuditAccessed). The table has no implicit per-user filter, so scoping is applied here.
type QueryService struct {
	store store.Store
	log   *Log
}

// NewQueryService builds the reader.
func NewQueryService(s store.Store, log *Log) *QueryService {
	return &QueryService{store: s, log: log}
}

// Query reads a page (newest first) and records that the trail was accessed.
func (q *QueryService) Query(ctx context.Context, query Query) (Result, error) {
	caller := contracts.CallerFrom(ctx)

	limit := query.Limit
	if limit < 1 {
		limit = 1
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}
	offset := query.Offset
	if offset < 0 {
		offset = 0
	}

	f := store.AuditFilter{
		UserID:       caller.UserID,
		TenantID:     caller.TenantID,
		Limit:        limit,
		Offset:       offset,
		FilterUserID: query.UserID,
		Since:        query.Since,
		Until:        query.Until,
	}
	if query.Type != nil {
		v := int(*query.Type)
		f.EventType = &v
	}
	if query.Outcome != nil {
		v := int(*query.Outcome)
		f.Outcome = &v
	}

	items, total, err := q.store.QueryAudit(ctx, f)
	if err != nil {
		return Result{}, err
	}

	q.log.Emit(ctx, EmitParams{Type: EventAuditAccessed, Outcome: OutcomeSuccess, TargetKind: "audit_log"})

	return Result{Items: items, Total: total, Limit: limit, Offset: offset}, nil
}
