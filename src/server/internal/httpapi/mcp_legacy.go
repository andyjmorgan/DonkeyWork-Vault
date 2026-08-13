package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/mcp"
	"donkeywork.dev/vault-server/internal/mcplegacy"
	"donkeywork.dev/vault-server/internal/store"
)

const (
	legacyMaxConcurrent = 8
	legacyIdleTimeout   = 30 * time.Minute
)

type legacyAdapterEntry struct {
	adapter *mcplegacy.Adapter
	key     string
}

func (s *Server) legacyLifecycleObserver(ctx context.Context, exchange *store.MCPAuditExchange, auditMode string, sequence *int64) mcplegacy.LifecycleObserver {
	return func(message mcplegacy.LifecycleMessage) error {
		direction := "client_to_server"
		kind := "notification"
		if message.Direction == mcplegacy.LifecycleFromUpstream {
			direction = "server_to_client"
			kind = "result"
		}
		record := rawMCPAuditRecord(exchange, *sequence, direction, kind, message.Body, auditMode)
		record.Method = &message.Method
		if message.Direction == mcplegacy.LifecycleFromUpstream {
			if inspected, err := mcp.InspectServer(message.Body, s.deps.MCPAuditHMACKey); err == nil {
				record.MessageKind = string(inspected.Kind)
				idKind, idValue := string(inspected.ID.Kind), inspected.ID.Value
				record.JSONRPCIDType, record.JSONRPCIDText = &idKind, emptyStringPtr(idValue)
				record.ResultType = emptyStringPtr(inspected.Audit.ResultType)
			}
		} else {
			var envelope struct {
				ID json.RawMessage `json:"id"`
			}
			if json.Unmarshal(message.Body, &envelope) == nil && len(envelope.ID) > 0 {
				record.MessageKind = "request"
				idKind, idValue := "string", ""
				_ = json.Unmarshal(envelope.ID, &idValue)
				record.JSONRPCIDType, record.JSONRPCIDText = &idKind, &idValue
			}
		}
		record.PolicyDecision = "allowed"
		if err := s.deps.MCP.Store().InsertMCPAuditMessage(ctx, record); err != nil {
			return err
		}
		*sequence++
		return nil
	}
}

type legacyAdapterPool struct {
	mu      sync.Mutex
	entries map[uuid.UUID]legacyAdapterEntry
}

func newLegacyAdapterPool() *legacyAdapterPool {
	return &legacyAdapterPool{entries: make(map[uuid.UUID]legacyAdapterEntry)}
}

func (p *legacyAdapterPool) adapter(connection store.MCPConnection, client *http.Client, serviceVersion string) (*mcplegacy.Adapter, error) {
	key := connection.UpstreamURL + "\x00" + connection.LegacyProtocolVersion
	p.mu.Lock()
	defer p.mu.Unlock()
	if entry, ok := p.entries[connection.ID]; ok {
		if entry.adapter.ExpireIdle(time.Now()) {
			delete(p.entries, connection.ID)
		} else if entry.key == key {
			return entry.adapter, nil
		}
	}
	adapter, err := mcplegacy.New(mcplegacy.Config{
		Endpoint: connection.UpstreamURL, Client: client, ProtocolVersion: connection.LegacyProtocolVersion,
		ClientName: "DonkeyWork Vault", ClientVersion: serviceVersion, MaxConcurrent: legacyMaxConcurrent,
		MaxBodyBytes: maxRequestBody, IdleTimeout: legacyIdleTimeout,
	})
	if err != nil {
		return nil, err
	}
	p.entries[connection.ID] = legacyAdapterEntry{adapter: adapter, key: key}
	return adapter, nil
}

func (p *legacyAdapterPool) expireIdle(now time.Time) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	expired := 0
	for id, entry := range p.entries {
		if entry.adapter.ExpireIdle(now) {
			delete(p.entries, id)
			expired++
		}
	}
	return expired
}

func (p *legacyAdapterPool) remove(ctx context.Context, id uuid.UUID, template *http.Request) error {
	p.mu.Lock()
	entry, ok := p.entries[id]
	if ok {
		delete(p.entries, id)
	}
	p.mu.Unlock()
	if !ok {
		return nil
	}
	// Administrative deletion must not wait behind a long-lived upstream stream. Without fresh
	// authorization headers there is no safe DELETE to send, so discard the pool reference and let
	// any in-flight request finish under its own context.
	if template == nil {
		return nil
	}
	return entry.adapter.Close(ctx, template)
}
