package db_test

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"donkeywork.dev/vault-server/internal/db"
)

// migrateTestDB is a dedicated database the migrate tests own end-to-end, so they never race the
// store package's tests (which share VAULT_TEST_DSN and its `vault` schema) when both packages run
// concurrently under `go test ./...`.
const migrateTestDB = "vault_migrate_test"

// dsnForDB rewrites the path of the configured VAULT_TEST_DSN to point at a different database.
func dsnForDB(t *testing.T, dsn, dbName string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	u.Path = "/" + dbName
	return u.String()
}

// freshMigrateDB drops and recreates the isolated migrate test database and returns a pool to it.
// The caller is responsible for closing the returned pool.
func freshMigrateDB(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("admin pool: %v", err)
	}
	defer admin.Close()
	// DROP/CREATE DATABASE cannot run inside the connection that may hold it open; a fresh admin
	// pool to the default database is fine here.
	if _, err := admin.Exec(ctx, `DROP DATABASE IF EXISTS `+migrateTestDB+` WITH (FORCE)`); err != nil {
		t.Fatalf("drop db: %v", err)
	}
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+migrateTestDB); err != nil {
		t.Fatalf("create db: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsnForDB(t, dsn, migrateTestDB))
	if err != nil {
		t.Fatalf("target pool: %v", err)
	}
	return pool
}

// TestMigrate exercises the full apply path against a freshly created database and the idempotent
// re-run (every migration already recorded, so the loop hits the "exists" continue).
func TestMigrate(t *testing.T) {
	dsn := os.Getenv("VAULT_TEST_DSN")
	if dsn == "" {
		t.Skip("VAULT_TEST_DSN not set")
	}
	ctx := context.Background()
	pool := freshMigrateDB(t, dsn)
	defer pool.Close()

	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	// Second run is a no-op: all versions already recorded (idempotency path).
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("idempotent migrate: %v", err)
	}
	// Sanity: the schema and at least one expected table exist after migration.
	var ok bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema='vault' AND table_name='access_keys')`).Scan(&ok); err != nil || !ok {
		t.Fatalf("expected vault.access_keys after migrate: ok=%v err=%v", ok, err)
	}
}

// TestMigrateClosedPool drives the early failure path: acquiring a connection from a closed pool
// returns an error before any SQL runs (the acquire-migration-connection branch).
func TestMigrateClosedPool(t *testing.T) {
	dsn := os.Getenv("VAULT_TEST_DSN")
	if dsn == "" {
		t.Skip("VAULT_TEST_DSN not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	err = db.Migrate(ctx, pool)
	if err == nil {
		t.Fatal("expected error migrating with a closed pool")
	}
	if !strings.Contains(err.Error(), "acquire migration connection") {
		t.Fatalf("expected acquire-connection error, got: %v", err)
	}
}

// withRestrictedRole creates a throwaway login role with no schema/table-creation rights, returns
// a pool connected as that role to dbName, and a cleanup func. The role can connect (and take
// advisory locks) but its DDL is denied — driving Migrate's CREATE error branches.
func withRestrictedRole(t *testing.T, dsn, dbName string, grant func(admin *pgxpool.Pool)) (*pgxpool.Pool, func()) {
	t.Helper()
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsnForDB(t, dsn, dbName))
	if err != nil {
		t.Fatalf("admin pool: %v", err)
	}
	role := strings.ToLower("vault_ro_" + strings.ReplaceAll(t.Name(), "/", "_"))
	_, _ = admin.Exec(ctx, `DROP ROLE IF EXISTS `+role)
	if _, err := admin.Exec(ctx, `CREATE ROLE `+role+` LOGIN PASSWORD 'ro'`); err != nil {
		admin.Close()
		t.Fatalf("create role: %v", err)
	}
	if _, err := admin.Exec(ctx, `GRANT CONNECT ON DATABASE `+dbName+` TO `+role); err != nil {
		admin.Close()
		t.Fatalf("grant connect: %v", err)
	}
	// Revoke the implicit CREATE on the public schema / database so DDL is denied.
	_, _ = admin.Exec(ctx, `REVOKE CREATE ON DATABASE `+dbName+` FROM `+role)
	if grant != nil {
		grant(admin)
	}

	u, _ := url.Parse(dsnForDB(t, dsn, dbName))
	u.User = url.UserPassword(role, "ro")
	rpool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		admin.Close()
		t.Fatalf("restricted pool: %v", err)
	}
	cleanup := func() {
		rpool.Close()
		cctx := context.Background()
		// A role can't be dropped while it holds privileges/owns objects; clear them first.
		_, _ = admin.Exec(cctx, `REVOKE ALL ON DATABASE `+dbName+` FROM `+role)
		_, _ = admin.Exec(cctx, `DROP OWNED BY `+role+` CASCADE`)
		_, _ = admin.Exec(cctx, `DROP ROLE IF EXISTS `+role)
		admin.Close()
	}
	return rpool, cleanup
}

// TestMigrateCreateSchemaDenied drives the ensure-schema error branch: the connecting role lacks
// CREATE on the database, so `CREATE SCHEMA IF NOT EXISTS vault` is denied.
func TestMigrateCreateSchemaDenied(t *testing.T) {
	dsn := os.Getenv("VAULT_TEST_DSN")
	if dsn == "" {
		t.Skip("VAULT_TEST_DSN not set")
	}
	pool := freshMigrateDB(t, dsn)
	pool.Close()
	rpool, cleanup := withRestrictedRole(t, dsn, migrateTestDB, nil)
	defer cleanup()
	err := db.Migrate(context.Background(), rpool)
	if err == nil {
		t.Fatal("expected ensure-schema permission error")
	}
	if !strings.Contains(err.Error(), "ensure schema") {
		t.Fatalf("expected ensure-schema error, got: %v", err)
	}
}

// TestMigrateCreateMigrationsTableDenied drives the ensure-migrations-table error branch: the
// vault schema already exists (so CREATE SCHEMA IF NOT EXISTS is a no-op) but the role has only
// USAGE on it, so creating schema_migrations is denied.
func TestMigrateCreateMigrationsTableDenied(t *testing.T) {
	dsn := os.Getenv("VAULT_TEST_DSN")
	if dsn == "" {
		t.Skip("VAULT_TEST_DSN not set")
	}
	ctx := context.Background()
	pool := freshMigrateDB(t, dsn)
	if _, err := pool.Exec(ctx, `CREATE SCHEMA vault`); err != nil {
		t.Fatal(err)
	}
	pool.Close()
	rpool, cleanup := withRestrictedRole(t, dsn, migrateTestDB, func(admin *pgxpool.Pool) {
		role := strings.ToLower("vault_ro_" + strings.ReplaceAll(t.Name(), "/", "_"))
		// Re-grant CREATE on the database so `CREATE SCHEMA IF NOT EXISTS vault` passes (the schema
		// already exists), but the role gets only USAGE on the vault schema — so creating the
		// schema_migrations table inside it is denied.
		_, _ = admin.Exec(context.Background(), `GRANT CREATE ON DATABASE `+migrateTestDB+` TO `+role)
		_, _ = admin.Exec(context.Background(), `GRANT USAGE ON SCHEMA vault TO `+role)
	})
	defer cleanup()
	err := db.Migrate(ctx, rpool)
	if err == nil {
		t.Fatal("expected ensure-migrations-table permission error")
	}
	if !strings.Contains(err.Error(), "ensure migrations table") {
		t.Fatalf("expected ensure-migrations-table error, got: %v", err)
	}
}

// TestMigrateVersionCheckError pre-creates a malformed vault.schema_migrations (no `version`
// column) so the per-migration `SELECT EXISTS(... WHERE version=$1)` query fails — covering the
// version-check error branch. CREATE TABLE IF NOT EXISTS inside Migrate then leaves the broken
// table as-is.
func TestMigrateVersionCheckError(t *testing.T) {
	dsn := os.Getenv("VAULT_TEST_DSN")
	if dsn == "" {
		t.Skip("VAULT_TEST_DSN not set")
	}
	ctx := context.Background()
	pool := freshMigrateDB(t, dsn)
	defer pool.Close()

	if _, err := pool.Exec(ctx, `CREATE SCHEMA vault`); err != nil {
		t.Fatal(err)
	}
	// Table exists but lacks the `version` column the query references.
	if _, err := pool.Exec(ctx, `CREATE TABLE vault.schema_migrations (other text)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, pool); err == nil {
		t.Fatal("expected version-check query error")
	}
}

// TestMigrateRecordVersionError drives the record-version error + rollback branch: the migration
// body applies cleanly, but a BEFORE INSERT trigger on schema_migrations raises, so recording the
// applied version fails inside the transaction.
func TestMigrateRecordVersionError(t *testing.T) {
	dsn := os.Getenv("VAULT_TEST_DSN")
	if dsn == "" {
		t.Skip("VAULT_TEST_DSN not set")
	}
	ctx := context.Background()
	pool := freshMigrateDB(t, dsn)
	defer pool.Close()

	// Pre-build the schema + a correctly-shaped migrations table so Migrate's CREATE IF NOT EXISTS
	// statements and the EXISTS check all succeed and the loop proceeds to apply 0001.
	if _, err := pool.Exec(ctx, `CREATE SCHEMA vault`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE vault.schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	// Trigger that blocks any INSERT — only the version-recording INSERT hits it.
	if _, err := pool.Exec(ctx, `
		CREATE FUNCTION vault.block_insert() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'blocked'; END; $$ LANGUAGE plpgsql;
		CREATE TRIGGER block_sm BEFORE INSERT ON vault.schema_migrations FOR EACH ROW EXECUTE FUNCTION vault.block_insert();`); err != nil {
		t.Fatal(err)
	}
	err := db.Migrate(ctx, pool)
	if err == nil {
		t.Fatal("expected record-version error")
	}
	if !strings.Contains(err.Error(), "record 0001_baseline") {
		t.Fatalf("expected record error, got: %v", err)
	}
}

// TestMigrateCommitError drives the commit-error branch: a DEFERRABLE INITIALLY DEFERRED foreign
// key on schema_migrations is satisfied at INSERT time but checked at COMMIT, where it fails — so
// the body applies, the version INSERT succeeds, and only tx.Commit returns an error.
func TestMigrateCommitError(t *testing.T) {
	dsn := os.Getenv("VAULT_TEST_DSN")
	if dsn == "" {
		t.Skip("VAULT_TEST_DSN not set")
	}
	ctx := context.Background()
	pool := freshMigrateDB(t, dsn)
	defer pool.Close()

	if _, err := pool.Exec(ctx, `CREATE SCHEMA vault`); err != nil {
		t.Fatal(err)
	}
	// A parent table with no rows, and a schema_migrations whose `dep` column defaults to a value
	// that has no parent. The FK is deferred, so the violation surfaces at COMMIT, not at INSERT.
	if _, err := pool.Exec(ctx, `
		CREATE TABLE vault.parent (id uuid PRIMARY KEY);
		CREATE TABLE vault.schema_migrations (
			version text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now(),
			dep uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001'
				REFERENCES vault.parent(id) DEFERRABLE INITIALLY DEFERRED);`); err != nil {
		t.Fatal(err)
	}
	err := db.Migrate(ctx, pool)
	if err == nil {
		t.Fatal("expected commit error")
	}
	if !strings.Contains(err.Error(), "commit 0001_baseline") {
		t.Fatalf("expected commit error, got: %v", err)
	}
}

// TestMigrateApplyError drives the migration-body failure + rollback branch: the access_keys table
// is pre-created without the key_hash column, so the body's `CREATE TABLE IF NOT EXISTS` is a no-op
// but its `CREATE UNIQUE INDEX ... (key_hash)` errors inside the transaction.
func TestMigrateApplyError(t *testing.T) {
	dsn := os.Getenv("VAULT_TEST_DSN")
	if dsn == "" {
		t.Skip("VAULT_TEST_DSN not set")
	}
	ctx := context.Background()
	pool := freshMigrateDB(t, dsn)
	defer pool.Close()

	if _, err := pool.Exec(ctx, `CREATE SCHEMA vault`); err != nil {
		t.Fatal(err)
	}
	// Conflicting table shape: exists (so CREATE TABLE IF NOT EXISTS skips) but missing key_hash,
	// which the index in the same migration body requires.
	if _, err := pool.Exec(ctx, `CREATE TABLE vault.access_keys (id uuid)`); err != nil {
		t.Fatal(err)
	}
	err := db.Migrate(ctx, pool)
	if err == nil {
		t.Fatal("expected migration apply error")
	}
	if !strings.Contains(err.Error(), "apply 0001_baseline") {
		t.Fatalf("expected apply error, got: %v", err)
	}
}
