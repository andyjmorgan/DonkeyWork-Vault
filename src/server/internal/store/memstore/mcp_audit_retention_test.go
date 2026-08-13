package memstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/store"
)

func TestMCPAuditRetention(t *testing.T) {
	ctx := context.Background()
	m := New()
	userID, tenantID, connectionID, accessKeyID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC()
	seed := func(startedAt time.Time) *store.MCPAuditExchange {
		t.Helper()
		completedAt := startedAt.Add(time.Minute)
		exchange := &store.MCPAuditExchange{ConnectionID: connectionID, UserID: userID, TenantID: tenantID,
			AccessKeyID: accessKeyID, HTTPMethod: "POST", ProtocolVersion: "2026-07-28", Outcome: "complete", StartedAt: startedAt, CompletedAt: &completedAt}
		if err := m.InsertMCPAuditExchange(ctx, exchange); err != nil {
			t.Fatal(err)
		}
		message := &store.MCPAuditMessage{ExchangeID: exchange.ID, ConnectionID: connectionID,
			UserID: userID, TenantID: tenantID, SequenceNo: 1, ObservedAt: startedAt,
			Direction: "client_to_server", MessageKind: "request", PolicyDecision: "allowed",
			PayloadSHA256: []byte{1}, PayloadBytes: 1}
		if err := m.InsertMCPAuditMessage(ctx, message); err != nil {
			t.Fatal(err)
		}
		return exchange
	}
	oldest := seed(now.Add(-72 * time.Hour))
	middle := seed(now.Add(-48 * time.Hour))
	newest := seed(now.Add(-time.Hour))
	inFlight := seed(now.Add(-96 * time.Hour))
	inFlight.CompletedAt = nil
	m.mcpExchanges[inFlight.ID] = *inFlight

	deleted, err := m.DeleteMCPAuditOlderThan(ctx, now.Add(-24*time.Hour), 1)
	if err != nil || deleted != 1 {
		t.Fatalf("first batch: deleted=%d err=%v", deleted, err)
	}
	if err := m.InsertMCPAuditMessage(ctx, &store.MCPAuditMessage{ExchangeID: oldest.ID, ConnectionID: connectionID, UserID: userID, TenantID: tenantID}); !errors.Is(err, store.ErrOwnershipMismatch) {
		t.Fatalf("oldest parent retained: %v", err)
	}
	rows, total, err := m.QueryMCPAudit(ctx, store.MCPAuditFilter{UserID: userID, TenantID: tenantID, Limit: 10})
	if err != nil || total != 3 || len(rows) != 3 {
		t.Fatalf("message cascade: rows=%d total=%d err=%v", len(rows), total, err)
	}
	if rows[0].ExchangeID != newest.ID || rows[1].ExchangeID != middle.ID || rows[2].ExchangeID != inFlight.ID {
		t.Fatalf("wrong exchanges retained: %+v", rows)
	}
	deleted, err = m.DeleteMCPAuditOlderThan(ctx, now.Add(-24*time.Hour), 10)
	if err != nil || deleted != 1 {
		t.Fatalf("second batch: deleted=%d err=%v", deleted, err)
	}
	rows, total, _ = m.QueryMCPAudit(ctx, store.MCPAuditFilter{UserID: userID, TenantID: tenantID, Limit: 10})
	if total != 2 || rows[0].ExchangeID != newest.ID || rows[1].ExchangeID != inFlight.ID {
		t.Fatalf("new exchange not retained: %+v", rows)
	}
	if deleted, err = m.DeleteMCPAuditOlderThan(ctx, now.Add(-24*time.Hour), 10); err != nil || deleted != 0 {
		t.Fatalf("empty batch: deleted=%d err=%v", deleted, err)
	}
}

func TestMCPAuditRetentionFailureInjection(t *testing.T) {
	m := New()
	if deleted, err := m.DeleteMCPAuditOlderThan(context.Background(), time.Now(), 0); err != nil || deleted != 0 {
		t.Fatalf("zero batch: deleted=%d err=%v", deleted, err)
	}
	boom := errors.New("boom")
	m.FailNext = boom
	if _, err := m.DeleteMCPAuditOlderThan(context.Background(), time.Now(), 10); !errors.Is(err, boom) {
		t.Fatalf("failure: %v", err)
	}
}
