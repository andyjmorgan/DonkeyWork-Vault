package store

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const mcpOAuthUnlockTimeout = 5 * time.Second

func mcpOAuthRefreshLockKey(connectionID uuid.UUID) int64 {
	digest := sha256.Sum256(append([]byte("dwv:mcp-oauth-refresh:"), connectionID[:]...))
	return int64(binary.BigEndian.Uint64(digest[:8]) & math.MaxInt64)
}

// WithMCPOAuthRefreshLock runs fn while holding a session lock on a dedicated database connection.
func (p *Postgres) WithMCPOAuthRefreshLock(ctx context.Context, connectionID uuid.UUID, fn func() error) (err error) {
	connection, err := p.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	reusable := false
	defer func() {
		if reusable {
			connection.Release()
			return
		}
		discardPoolConnection(ctx, connection)
	}()

	key := mcpOAuthRefreshLockKey(connectionID)
	if _, err := connection.Exec(ctx, `SELECT pg_advisory_lock($1)`, key); err != nil {
		return fmt.Errorf("acquire MCP OAuth refresh lock: %w", err)
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mcpOAuthUnlockTimeout)
		defer cancel()
		var unlocked bool
		unlockErr := connection.QueryRow(unlockCtx, `SELECT pg_advisory_unlock($1)`, key).Scan(&unlocked)
		if unlockErr != nil {
			err = errors.Join(err, fmt.Errorf("release MCP OAuth refresh lock: %w", unlockErr))
			return
		}
		if !unlocked {
			err = errors.Join(err, errors.New("release MCP OAuth refresh lock: lock was not held"))
			return
		}
		reusable = true
	}()
	return fn()
}

func discardPoolConnection(ctx context.Context, connection *pgxpool.Conn) {
	physical := connection.Hijack()
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mcpOAuthUnlockTimeout)
	defer cancel()
	_ = physical.Close(closeCtx)
}
