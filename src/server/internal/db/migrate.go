// Package db owns schema migrations for the vault. Migrations are plain .sql files embedded into the
// binary and applied in lexical order inside a transaction, with applied versions recorded in
// vault.schema_migrations. This is deliberately a tiny runner rather than a dependency: the schema
// is small, and keeping the SQL in-repo (not generated) makes every change to the credential and
// audit tables reviewable.
package db

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrateLockKey is an arbitrary advisory-lock key serialising migration runs across replicas.
const migrateLockKey = 0x76_61_75_6c_74 // "vault"

// Migrate applies all embedded migrations that have not yet been recorded. It is safe to run on
// every startup and against an already-populated database. A session advisory
// lock serialises concurrent replicas (the loser waits, then sees the versions as applied).
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	lockConn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer lockConn.Release()
	if _, err := lockConn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrateLockKey); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err) //coverage:ignore pg_advisory_lock cannot fail on a live acquired connection
	}
	defer func() {
		_, _ = lockConn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrateLockKey)
	}()

	if _, err := pool.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS vault`); err != nil {
		return fmt.Errorf("ensure schema: %w", err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS vault.schema_migrations (
			version    text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("ensure migrations table: %w", err)
	}

	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return err //coverage:ignore migrationsFS is a compiled-in embed.FS; ReadDir cannot fail at runtime
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		version := strings.TrimSuffix(name, ".sql")
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM vault.schema_migrations WHERE version=$1)`, version).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}

		body, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return err //coverage:ignore name came from the embed.FS dir listing; ReadFile cannot fail at runtime
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err //coverage:ignore Begin on a healthy pool that just executed queries does not fail
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO vault.schema_migrations (version) VALUES ($1)`, version); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit %s: %w", name, err)
		}
	}
	return nil
}
