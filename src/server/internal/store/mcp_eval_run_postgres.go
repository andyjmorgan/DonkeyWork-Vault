package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const mcpEvalRunCols = `id, user_id, tenant_id, run_id, access_key_id, expires_at, revoked_at, created_at`

func scanMCPEvalRun(row pgx.Row) (*MCPEvalRun, error) {
	var run MCPEvalRun
	err := row.Scan(&run.ID, &run.UserID, &run.TenantID, &run.RunID, &run.AccessKeyID,
		&run.ExpiresAt, &run.RevokedAt, &run.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &run, nil
}

// CreateMCPEvalRun atomically creates an access key, run and connection grants.
func (p *Postgres) CreateMCPEvalRun(ctx context.Context, run *MCPEvalRun, key *AccessKey, connectionIDs []uuid.UUID) error {
	if err := ValidateMCPEvalRunCreation(run, key, connectionIDs, time.Now().UTC()); err != nil {
		return err
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		SELECT id FROM vault.mcp_connections
		WHERE id=ANY($1) AND user_id=$2 AND tenant_id=$3 AND enabled=true
		FOR UPDATE`, connectionIDs, run.UserID, run.TenantID)
	if err != nil {
		return err
	}
	owned := 0
	for rows.Next() {
		owned++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if owned != len(connectionIDs) {
		return ErrOwnershipMismatch
	}

	var keyID uuid.UUID
	var keyCreatedAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO vault.access_keys
			(user_id, tenant_id, name, description, key_hash, key_prefix, scopes, enabled, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id, created_at`, key.UserID, key.TenantID, key.Name, key.Description, key.KeyHash,
		key.KeyPrefix, key.Scopes, key.Enabled, key.ExpiresAt).Scan(&keyID, &keyCreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: duplicate access key", ErrInvalidMCPEvalRun)
		}
		return err
	}

	var runID uuid.UUID
	var runCreatedAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO vault.mcp_eval_runs (user_id, tenant_id, run_id, access_key_id, expires_at)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING id, created_at`, run.UserID, run.TenantID, run.RunID, keyID, run.ExpiresAt).
		Scan(&runID, &runCreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: duplicate run ID", ErrInvalidMCPEvalRun)
		}
		return err
	}

	tag, err := tx.Exec(ctx, `
		INSERT INTO vault.mcp_connection_grants
			(user_id, tenant_id, connection_id, access_key_id)
		SELECT $1,$2,connection_id,$4 FROM unnest($3::uuid[]) AS connection_id`,
		run.UserID, run.TenantID, connectionIDs, keyID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != int64(len(connectionIDs)) {
		return fmt.Errorf("create MCP eval run: inserted %d of %d grants", tag.RowsAffected(), len(connectionIDs))
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	key.ID = keyID
	key.CreatedAt = keyCreatedAt
	run.ID = runID
	run.AccessKeyID = keyID
	run.CreatedAt = runCreatedAt
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// ListMCPEvalRuns returns an owner's eval runs, newest first.
func (p *Postgres) ListMCPEvalRuns(ctx context.Context, userID uuid.UUID) ([]MCPEvalRun, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+mcpEvalRunCols+` FROM vault.mcp_eval_runs WHERE user_id=$1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MCPEvalRun
	for rows.Next() {
		run, err := scanMCPEvalRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *run)
	}
	return out, rows.Err()
}

// GetMCPEvalRunByAccessKey returns the run owning an authenticated access key.
func (p *Postgres) GetMCPEvalRunByAccessKey(ctx context.Context, accessKeyID uuid.UUID) (*MCPEvalRun, error) {
	run, err := scanMCPEvalRun(p.pool.QueryRow(ctx, `SELECT `+mcpEvalRunCols+` FROM vault.mcp_eval_runs WHERE access_key_id=$1`, accessKeyID))
	if noRows(err) {
		return nil, nil
	}
	return run, err
}

// RevokeMCPEvalRun revokes an owner-scoped run and disables its access key atomically.
func (p *Postgres) RevokeMCPEvalRun(ctx context.Context, userID, id uuid.UUID) (bool, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var accessKeyID uuid.UUID
	err = tx.QueryRow(ctx, `
		UPDATE vault.mcp_eval_runs SET revoked_at=now()
		WHERE user_id=$1 AND id=$2 AND revoked_at IS NULL
		RETURNING access_key_id`, userID, id).Scan(&accessKeyID)
	if noRows(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx, `UPDATE vault.access_keys SET enabled=false, updated_at=now() WHERE id=$1`, accessKeyID)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() != 1 {
		return false, fmt.Errorf("revoke MCP eval run: access key %s not found", accessKeyID)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}
