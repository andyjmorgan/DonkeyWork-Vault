package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"

	"donkeywork.dev/vault-server/internal/audit"
	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/store"
)

const (
	mcpEvalRunMaxLifetime = 24 * time.Hour
	mcpEvalRunScope       = "vault:mcp"
	mcpEvalKeyNamePrefix  = "mcp-eval-"
)

// MCPEvalRunCredential contains an eval run's persisted metadata and show-once access-key secret.
type MCPEvalRunCredential struct {
	Run         store.MCPEvalRun
	Secret      string
	Connections []store.MCPConnection
}

// MCPEvalRunService manages short-lived, connection-scoped credentials for MCP eval sandboxes.
type MCPEvalRunService struct {
	store store.Store
	audit *audit.Log
	now   func() time.Time
}

// NewMCPEvalRunService builds the eval-run credential service.
func NewMCPEvalRunService(s store.Store, a *audit.Log) *MCPEvalRunService {
	return &MCPEvalRunService{store: s, audit: a, now: time.Now}
}

// Create mints a show-once access key and atomically grants it access to the requested connections.
func (s *MCPEvalRunService) Create(ctx context.Context, runID string, connectionIDs []uuid.UUID, expiresAt time.Time) (*MCPEvalRunCredential, error) {
	ctx, span := startSpan(ctx, "mcp.eval_run.create")
	defer span.End()

	runID = strings.TrimSpace(runID)
	span.SetAttributes(attribute.String("mcp.eval_run.id", runID))
	if runID == "" {
		return nil, ValidationError{"runId is required."}
	}
	if len(runID) > 255 {
		return nil, ValidationError{"runId must be at most 255 characters."}
	}
	if len(connectionIDs) == 0 {
		return nil, ValidationError{"at least one connectionId is required."}
	}

	seen := make(map[uuid.UUID]struct{}, len(connectionIDs))
	for _, connectionID := range connectionIDs {
		if connectionID == uuid.Nil {
			return nil, ValidationError{"connectionIds must not contain an empty UUID."}
		}
		if _, exists := seen[connectionID]; exists {
			return nil, ValidationError{"connectionIds must be unique."}
		}
		seen[connectionID] = struct{}{}
	}

	now := s.now()
	if !expiresAt.After(now) {
		return nil, ValidationError{"expiresAt must be in the future."}
	}
	if expiresAt.After(now.Add(mcpEvalRunMaxLifetime)) {
		return nil, ValidationError{"expiresAt must be no more than 24 hours in the future."}
	}

	caller := contracts.CallerFrom(ctx)
	connections := make([]store.MCPConnection, 0, len(connectionIDs))
	for _, connectionID := range connectionIDs {
		connection, err := s.store.GetMCPConnectionByID(ctx, caller.UserID, connectionID)
		if err != nil {
			return nil, err
		}
		if connection == nil {
			return nil, ValidationError{fmt.Sprintf("connection %s was not found.", connectionID)}
		}
		if !connection.Enabled {
			return nil, ValidationError{fmt.Sprintf("connection %s is disabled.", connectionID)}
		}
		connections = append(connections, *connection)
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err //coverage:ignore crypto/rand.Read does not fail in practice and is not injectable here
	}
	secret := SecretPrefix + base64.RawURLEncoding.EncodeToString(raw)
	prefix := secret
	if len(prefix) > 9 {
		prefix = secret[:9]
	}

	keyName := mcpEvalKeyNamePrefix + runID
	if len(keyName) > 255 {
		keyName = keyName[:255]
	}
	description := "Short-lived access key for MCP eval run " + runID
	key := &store.AccessKey{
		UserID:      caller.UserID,
		TenantID:    caller.TenantID,
		Name:        keyName,
		Description: &description,
		KeyHash:     hashSecret(secret),
		KeyPrefix:   prefix,
		Scopes:      []string{mcpEvalRunScope},
		Enabled:     true,
		ExpiresAt:   &expiresAt,
	}
	run := &store.MCPEvalRun{
		UserID:    caller.UserID,
		TenantID:  caller.TenantID,
		RunID:     runID,
		ExpiresAt: expiresAt,
	}
	if err := s.store.CreateMCPEvalRun(ctx, run, key, connectionIDs); err != nil {
		if errors.Is(err, store.ErrInvalidMCPEvalRun) {
			return nil, ValidationError{"runId already exists or the eval run is invalid."}
		}
		if errors.Is(err, store.ErrOwnershipMismatch) {
			return nil, ValidationError{"all connections must be enabled and owned by the caller."}
		}
		return nil, err
	}

	s.audit.Emit(ctx, audit.EmitParams{
		Type:       audit.EventCredentialCreated,
		Outcome:    audit.OutcomeSuccess,
		TargetKind: "mcp_eval_run",
		TargetName: runID,
	})
	return &MCPEvalRunCredential{Run: *run, Secret: secret, Connections: connections}, nil
}

// List returns the caller's eval runs.
func (s *MCPEvalRunService) List(ctx context.Context) ([]store.MCPEvalRun, error) {
	ctx, span := startSpan(ctx, "mcp.eval_run.list")
	defer span.End()
	return s.store.ListMCPEvalRuns(ctx, contracts.CallerFrom(ctx).UserID)
}

// Revoke disables an eval run's access key and marks the run revoked atomically.
func (s *MCPEvalRunService) Revoke(ctx context.Context, id uuid.UUID) (bool, error) {
	ctx, span := startSpan(ctx, "mcp.eval_run.revoke")
	defer span.End()
	return s.store.RevokeMCPEvalRun(ctx, contracts.CallerFrom(ctx).UserID, id)
}
