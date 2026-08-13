package memstore

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/store"
)

func TestMCPToolParameterHeadersReplace(t *testing.T) {
	ctx := context.Background()
	m := New()
	userID, tenantID := uuid.New(), uuid.New()
	connection := &store.MCPConnection{UserID: userID, TenantID: tenantID, Slug: "server"}
	if err := m.InsertMCPConnection(ctx, connection); err != nil {
		t.Fatal(err)
	}
	headers := []store.MCPToolParameterHeader{
		{ToolName: "search", HeaderName: "Tenant", ArgumentPath: []string{"filters", "tenant"}, Required: true},
		{ToolName: "search", HeaderName: "Region", ArgumentPath: []string{"region"}},
		{ToolName: "fetch", HeaderName: "Document", ArgumentPath: []string{"id"}, Required: true},
	}
	if err := m.ReplaceMCPToolParameterHeaders(ctx, userID, tenantID, connection.ID, headers); err != nil {
		t.Fatal(err)
	}
	for i, header := range headers {
		if header.ID == uuid.Nil || header.CreatedAt.IsZero() || header.UserID != userID ||
			header.TenantID != tenantID || header.ConnectionID != connection.ID {
			t.Fatalf("header %d generated fields: %+v", i, header)
		}
	}
	search, err := m.ListMCPToolParameterHeaders(ctx, userID, connection.ID, "search")
	if err != nil || len(search) != 2 || search[0].HeaderName != "Region" || search[1].HeaderName != "Tenant" {
		t.Fatalf("list search: %+v %v", search, err)
	}
	search[0].ArgumentPath[0] = "mutated"
	again, _ := m.ListMCPToolParameterHeaders(ctx, userID, connection.ID, "search")
	if again[0].ArgumentPath[0] != "region" {
		t.Fatal("list must return argument path copies")
	}
	if other, _ := m.ListMCPToolParameterHeaders(ctx, uuid.New(), connection.ID, "search"); len(other) != 0 {
		t.Fatal("owner scope")
	}
	if missing, _ := m.ListMCPToolParameterHeaders(ctx, userID, connection.ID, "missing"); len(missing) != 0 {
		t.Fatal("tool scope")
	}

	replacement := []store.MCPToolParameterHeader{{ToolName: "search", HeaderName: "Site", ArgumentPath: []string{"site"}}}
	if err := m.ReplaceMCPToolParameterHeaders(ctx, userID, tenantID, connection.ID, replacement); err != nil {
		t.Fatal(err)
	}
	if old, _ := m.ListMCPToolParameterHeaders(ctx, userID, connection.ID, "fetch"); len(old) != 0 {
		t.Fatal("replacement must remove stale tools")
	}
	if current, _ := m.ListMCPToolParameterHeaders(ctx, userID, connection.ID, "search"); len(current) != 1 || current[0].HeaderName != "Site" {
		t.Fatalf("replacement: %+v", current)
	}
	if err := m.ReplaceMCPToolParameterHeaders(ctx, userID, tenantID, connection.ID, nil); err != nil {
		t.Fatal(err)
	}
	if current, _ := m.ListMCPToolParameterHeaders(ctx, userID, connection.ID, "search"); len(current) != 0 {
		t.Fatal("empty replacement must clear")
	}
}

func TestMCPToolParameterHeadersRejectInvalidWithoutMutation(t *testing.T) {
	ctx := context.Background()
	m := New()
	userID, tenantID := uuid.New(), uuid.New()
	connection := &store.MCPConnection{UserID: userID, TenantID: tenantID, Slug: "server"}
	_ = m.InsertMCPConnection(ctx, connection)
	original := []store.MCPToolParameterHeader{{ToolName: "search", HeaderName: "Region", ArgumentPath: []string{"region"}}}
	if err := m.ReplaceMCPToolParameterHeaders(ctx, userID, tenantID, connection.ID, original); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		headers []store.MCPToolParameterHeader
		want    error
	}{
		{name: "empty tool", headers: []store.MCPToolParameterHeader{{HeaderName: "X", ArgumentPath: []string{"x"}}}, want: store.ErrInvalidMCPToolParameterHeader},
		{name: "empty header", headers: []store.MCPToolParameterHeader{{ToolName: "t", ArgumentPath: []string{"x"}}}, want: store.ErrInvalidMCPToolParameterHeader},
		{name: "empty path", headers: []store.MCPToolParameterHeader{{ToolName: "t", HeaderName: "X"}}, want: store.ErrInvalidMCPToolParameterHeader},
		{name: "empty component", headers: []store.MCPToolParameterHeader{{ToolName: "t", HeaderName: "X", ArgumentPath: []string{""}}}, want: store.ErrInvalidMCPToolParameterHeader},
		{name: "case-insensitive duplicate", headers: []store.MCPToolParameterHeader{
			{ToolName: "t", HeaderName: "Region", ArgumentPath: []string{"a"}},
			{ToolName: "t", HeaderName: "region", ArgumentPath: []string{"b"}},
		}, want: store.ErrInvalidMCPToolParameterHeader},
		{name: "wrong embedded user", headers: []store.MCPToolParameterHeader{{UserID: uuid.New(), ToolName: "t", HeaderName: "X", ArgumentPath: []string{"x"}}}, want: store.ErrOwnershipMismatch},
		{name: "wrong embedded tenant", headers: []store.MCPToolParameterHeader{{TenantID: uuid.New(), ToolName: "t", HeaderName: "X", ArgumentPath: []string{"x"}}}, want: store.ErrOwnershipMismatch},
		{name: "wrong embedded connection", headers: []store.MCPToolParameterHeader{{ConnectionID: uuid.New(), ToolName: "t", HeaderName: "X", ArgumentPath: []string{"x"}}}, want: store.ErrOwnershipMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := m.ReplaceMCPToolParameterHeaders(ctx, userID, tenantID, connection.ID, test.headers); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
			got, _ := m.ListMCPToolParameterHeaders(ctx, userID, connection.ID, "search")
			if len(got) != 1 || got[0].HeaderName != "Region" {
				t.Fatalf("invalid replace mutated state: %+v", got)
			}
		})
	}
	if err := m.ReplaceMCPToolParameterHeaders(ctx, uuid.New(), tenantID, connection.ID, nil); !errors.Is(err, store.ErrOwnershipMismatch) {
		t.Fatalf("connection owner: %v", err)
	}
}

func TestMCPToolParameterHeadersPaginatedUpsert(t *testing.T) {
	ctx := context.Background()
	m := New()
	userID, tenantID := uuid.New(), uuid.New()
	connection := &store.MCPConnection{UserID: userID, TenantID: tenantID, Slug: "server"}
	_ = m.InsertMCPConnection(ctx, connection)
	initial := []store.MCPToolParameterHeader{
		{ToolName: "search", HeaderName: "Old", ArgumentPath: []string{"old"}},
		{ToolName: "fetch", HeaderName: "Document", ArgumentPath: []string{"id"}},
		{ToolName: "delete", HeaderName: "Confirm", ArgumentPath: []string{"confirm"}},
	}
	if err := m.ReplaceMCPToolParameterHeaders(ctx, userID, tenantID, connection.ID, initial); err != nil {
		t.Fatal(err)
	}
	snapshots := []store.MCPToolHeaderSnapshot{
		{ToolName: "search", Headers: []store.MCPToolParameterHeader{{HeaderName: "Region", ArgumentPath: []string{"region"}}}},
		{ToolName: "fetch", Headers: nil},
	}
	if err := m.UpsertMCPToolParameterHeaders(ctx, userID, tenantID, connection.ID, snapshots); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.ListMCPToolParameterHeaders(ctx, userID, connection.ID, "search"); len(got) != 1 || got[0].HeaderName != "Region" {
		t.Fatalf("observed replacement: %+v", got)
	}
	if got, _ := m.ListMCPToolParameterHeaders(ctx, userID, connection.ID, "fetch"); len(got) != 0 {
		t.Fatalf("observed empty clear: %+v", got)
	}
	if got, _ := m.ListMCPToolParameterHeaders(ctx, userID, connection.ID, "delete"); len(got) != 1 {
		t.Fatalf("unobserved tool must remain: %+v", got)
	}
	if snapshots[0].Headers[0].ID == uuid.Nil || snapshots[0].Headers[0].ToolName != "search" {
		t.Fatalf("generated metadata: %+v", snapshots[0].Headers[0])
	}

	invalid := []store.MCPToolHeaderSnapshot{
		{ToolName: "search", Headers: []store.MCPToolParameterHeader{{HeaderName: "One", ArgumentPath: []string{"one"}}}},
		{ToolName: "search"},
	}
	if err := m.UpsertMCPToolParameterHeaders(ctx, userID, tenantID, connection.ID, invalid); !errors.Is(err, store.ErrInvalidMCPToolParameterHeader) {
		t.Fatalf("duplicate snapshot: %v", err)
	}
	mismatch := []store.MCPToolHeaderSnapshot{{ToolName: "search", Headers: []store.MCPToolParameterHeader{{ToolName: "fetch", HeaderName: "One", ArgumentPath: []string{"one"}}}}}
	if err := m.UpsertMCPToolParameterHeaders(ctx, userID, tenantID, connection.ID, mismatch); !errors.Is(err, store.ErrInvalidMCPToolParameterHeader) {
		t.Fatalf("tool mismatch: %v", err)
	}
	if err := m.UpsertMCPToolParameterHeaders(ctx, uuid.New(), tenantID, connection.ID, nil); !errors.Is(err, store.ErrOwnershipMismatch) {
		t.Fatalf("connection owner: %v", err)
	}
	for name, snapshot := range map[string]store.MCPToolHeaderSnapshot{
		"wrong embedded user":       {ToolName: "search", Headers: []store.MCPToolParameterHeader{{UserID: uuid.New(), HeaderName: "X", ArgumentPath: []string{"x"}}}},
		"wrong embedded tenant":     {ToolName: "search", Headers: []store.MCPToolParameterHeader{{TenantID: uuid.New(), HeaderName: "X", ArgumentPath: []string{"x"}}}},
		"wrong embedded connection": {ToolName: "search", Headers: []store.MCPToolParameterHeader{{ConnectionID: uuid.New(), HeaderName: "X", ArgumentPath: []string{"x"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := m.UpsertMCPToolParameterHeaders(ctx, userID, tenantID, connection.ID, []store.MCPToolHeaderSnapshot{snapshot}); !errors.Is(err, store.ErrOwnershipMismatch) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestMCPToolParameterHeadersFailureInjection(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("boom")
	m := New()
	m.FailNext = boom
	if err := m.ReplaceMCPToolParameterHeaders(ctx, uuid.New(), uuid.New(), uuid.New(), nil); !errors.Is(err, boom) {
		t.Fatalf("replace: %v", err)
	}
	m.FailNext = boom
	if _, err := m.ListMCPToolParameterHeaders(ctx, uuid.New(), uuid.New(), "tool"); !errors.Is(err, boom) {
		t.Fatalf("list: %v", err)
	}
	m.FailNext = boom
	if err := m.UpsertMCPToolParameterHeaders(ctx, uuid.New(), uuid.New(), uuid.New(), nil); !errors.Is(err, boom) {
		t.Fatalf("upsert: %v", err)
	}
}
