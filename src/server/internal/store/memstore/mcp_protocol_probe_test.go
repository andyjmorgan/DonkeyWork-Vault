package memstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/store"
)

func TestMCPProtocolProbe(t *testing.T) {
	ctx := context.Background()
	m := New()
	userID, tenantID := uuid.New(), uuid.New()
	connection := &store.MCPConnection{UserID: userID, TenantID: tenantID, Slug: "probe", Name: "Before", UpstreamURL: "https://example.test/mcp"}
	if err := m.InsertMCPConnection(ctx, connection); err != nil {
		t.Fatal(err)
	}
	if connection.ProtocolEra != "unknown" || connection.ProbeStatus != "not_checked" {
		t.Fatalf("defaults: %+v", connection)
	}
	checkedAt := time.Now().UTC()
	detail, serverName, serverVersion := "modern stateless endpoint", "Acme MCP", "1.2.3"
	result := &store.MCPProtocolProbeResult{ConnectionID: connection.ID, UserID: userID, TenantID: tenantID,
		ProtocolEra: "modern_2026_07", Status: "compatible", CheckedAt: checkedAt,
		Detail: &detail, SupportedVersions: []string{"2026-07-28"}, ServerName: &serverName, ServerVersion: &serverVersion}
	if ok, err := m.RecordMCPProtocolProbe(ctx, result); err != nil || !ok {
		t.Fatalf("record: %v %v", ok, err)
	}
	got, _ := m.GetMCPConnectionByID(ctx, userID, connection.ID)
	if got == nil || got.ProtocolEra != result.ProtocolEra || got.ProbeStatus != result.Status ||
		got.ProbeCheckedAt == nil || !got.ProbeCheckedAt.Equal(checkedAt) || len(got.SupportedVersions) != 1 ||
		got.ServerName == nil || *got.ServerName != serverName {
		t.Fatalf("probe round trip: %+v", got)
	}

	// Editable updates preserve the independently owned probe fields.
	connection.Name = "After"
	if ok, err := m.UpdateMCPConnection(ctx, connection); err != nil || !ok {
		t.Fatalf("config update: %v %v", ok, err)
	}
	got, _ = m.GetMCPConnectionByID(ctx, userID, connection.ID)
	if got.Name != "After" || got.ProbeStatus != "compatible" || got.ServerVersion == nil {
		t.Fatalf("config update overwrote probe: %+v", got)
	}

	errorClass := "authentication_required"
	failed := &store.MCPProtocolProbeResult{ConnectionID: connection.ID, UserID: userID, TenantID: tenantID,
		ProtocolEra: "unknown", Status: "auth_required", CheckedAt: checkedAt.Add(time.Minute), Error: &errorClass}
	if ok, err := m.RecordMCPProtocolProbe(ctx, failed); err != nil || !ok {
		t.Fatalf("replace probe: %v %v", ok, err)
	}
	got, _ = m.GetMCPConnectionByID(ctx, userID, connection.ID)
	if got.ProbeError == nil || got.ProbeDetail != nil || got.ServerName != nil || len(got.SupportedVersions) != 0 {
		t.Fatalf("replacement did not clear prior result: %+v", got)
	}
	if ok, err := m.RecordMCPProtocolProbe(ctx, &store.MCPProtocolProbeResult{
		ConnectionID: connection.ID, UserID: uuid.New(), TenantID: tenantID,
		ProtocolEra: "unknown", Status: "error", CheckedAt: checkedAt,
	}); err != nil || ok {
		t.Fatalf("owner scope: %v %v", ok, err)
	}
}

func TestMCPProtocolProbeValidationAndFailure(t *testing.T) {
	valid := store.MCPProtocolProbeResult{ProtocolEra: "unknown", Status: "error", CheckedAt: time.Now()}
	tests := []struct {
		name   string
		mutate func(*store.MCPProtocolProbeResult)
	}{
		{name: "era", mutate: func(r *store.MCPProtocolProbeResult) { r.ProtocolEra = "future" }},
		{name: "status", mutate: func(r *store.MCPProtocolProbeResult) { r.Status = "maybe" }},
		{name: "time", mutate: func(r *store.MCPProtocolProbeResult) { r.CheckedAt = time.Time{} }},
		{name: "error length", mutate: func(r *store.MCPProtocolProbeResult) { value := strings.Repeat("x", 256); r.Error = &value }},
		{name: "detail length", mutate: func(r *store.MCPProtocolProbeResult) { value := strings.Repeat("x", 1025); r.Detail = &value }},
		{name: "name length", mutate: func(r *store.MCPProtocolProbeResult) { value := strings.Repeat("x", 256); r.ServerName = &value }},
		{name: "version length", mutate: func(r *store.MCPProtocolProbeResult) { value := strings.Repeat("x", 256); r.ServerVersion = &value }},
		{name: "empty supported version", mutate: func(r *store.MCPProtocolProbeResult) { r.SupportedVersions = []string{" "} }},
		{name: "long supported version", mutate: func(r *store.MCPProtocolProbeResult) { r.SupportedVersions = []string{strings.Repeat("x", 65)} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := valid
			test.mutate(&result)
			if err := store.ValidateMCPProtocolProbe(result); !errors.Is(err, store.ErrInvalidMCPProtocolProbe) {
				t.Fatalf("got %v", err)
			}
		})
	}
	m := New()
	if ok, err := m.RecordMCPProtocolProbe(context.Background(), nil); ok || !errors.Is(err, store.ErrInvalidMCPProtocolProbe) {
		t.Fatalf("nil result: %v %v", ok, err)
	}
	boom := errors.New("boom")
	m.FailNext = boom
	if _, err := m.RecordMCPProtocolProbe(context.Background(), &valid); !errors.Is(err, boom) {
		t.Fatalf("failure injection: %v", err)
	}
}
