package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/exaring/otelpgx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres is the pgx-backed Store. The pool is configured with an otelpgx query tracer, so every
// SQL statement issued here becomes a child span of the in-flight request — the DB layer of the
// traces pillar — annotated with the statement, without any per-call instrumentation code.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres opens a connection pool against dsn and verifies connectivity.
func NewPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	cfg.ConnConfig.Tracer = otelpgx.NewTracer(otelpgx.WithTrimSQLInSpanName())
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

// Pool exposes the underlying pool for the migration runner and tests.
func (p *Postgres) Pool() *pgxpool.Pool { return p.pool }

// Close releases the pool.
func (p *Postgres) Close() { p.pool.Close() }

func noRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// ---- access keys ----

func (p *Postgres) InsertAccessKey(ctx context.Context, k *AccessKey) error {
	return p.pool.QueryRow(ctx, `
		INSERT INTO vault.access_keys (user_id, tenant_id, name, description, key_hash, key_prefix, scopes, enabled)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id, created_at`,
		k.UserID, k.TenantID, k.Name, k.Description, k.KeyHash, k.KeyPrefix, k.Scopes, k.Enabled,
	).Scan(&k.ID, &k.CreatedAt)
}

const accessKeyCols = `id, user_id, tenant_id, name, description, key_hash, key_prefix, scopes, enabled, created_at, updated_at, last_used_at`

func scanAccessKey(row pgx.Row) (*AccessKey, error) {
	var k AccessKey
	err := row.Scan(&k.ID, &k.UserID, &k.TenantID, &k.Name, &k.Description, &k.KeyHash, &k.KeyPrefix,
		&k.Scopes, &k.Enabled, &k.CreatedAt, &k.UpdatedAt, &k.LastUsedAt)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func (p *Postgres) ListAccessKeys(ctx context.Context, userID uuid.UUID) ([]AccessKey, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+accessKeyCols+` FROM vault.access_keys WHERE user_id=$1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccessKey
	for rows.Next() {
		k, err := scanAccessKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

func (p *Postgres) GetAccessKeyByID(ctx context.Context, userID, id uuid.UUID) (*AccessKey, error) {
	k, err := scanAccessKey(p.pool.QueryRow(ctx, `SELECT `+accessKeyCols+` FROM vault.access_keys WHERE user_id=$1 AND id=$2`, userID, id))
	if noRows(err) {
		return nil, nil
	}
	return k, err
}

func (p *Postgres) SetAccessKeyEnabled(ctx context.Context, userID, id uuid.UUID, enabled bool) (*AccessKey, error) {
	k, err := scanAccessKey(p.pool.QueryRow(ctx, `
		UPDATE vault.access_keys SET enabled=$3, updated_at=now() WHERE user_id=$1 AND id=$2
		RETURNING `+accessKeyCols, userID, id, enabled))
	if noRows(err) {
		return nil, nil
	}
	return k, err
}

func (p *Postgres) DeleteAccessKey(ctx context.Context, userID, id uuid.UUID) (bool, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM vault.access_keys WHERE user_id=$1 AND id=$2`, userID, id)
	return tag.RowsAffected() > 0, err
}

func (p *Postgres) GetAccessKeyByHash(ctx context.Context, hash []byte) (*AccessKey, error) {
	k, err := scanAccessKey(p.pool.QueryRow(ctx, `SELECT `+accessKeyCols+` FROM vault.access_keys WHERE key_hash=$1`, hash))
	if noRows(err) {
		return nil, nil
	}
	return k, err
}

func (p *Postgres) TouchAccessKeyLastUsed(ctx context.Context, id uuid.UUID) error {
	_, err := p.pool.Exec(ctx, `UPDATE vault.access_keys SET last_used_at=now() WHERE id=$1`, id)
	return err
}

// ---- api keys ----

const apiKeyCols = `id, user_id, tenant_id, provider_key, name, fields_cipher, kind, description, base_url, docs_url, header_name, prefix, username, created_at, updated_at, last_used_at`

func scanAPIKey(row pgx.Row) (*APIKey, error) {
	var k APIKey
	err := row.Scan(&k.ID, &k.UserID, &k.TenantID, &k.ProviderKey, &k.Name, &k.FieldsCipher, &k.Kind,
		&k.Description, &k.BaseURL, &k.DocsURL, &k.HeaderName, &k.Prefix, &k.Username,
		&k.CreatedAt, &k.UpdatedAt, &k.LastUsedAt)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func (p *Postgres) InsertAPIKey(ctx context.Context, k *APIKey) error {
	return p.pool.QueryRow(ctx, `
		INSERT INTO vault.api_keys (user_id, tenant_id, provider_key, name, fields_cipher, kind, description, base_url, docs_url, header_name, prefix, username)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING id, created_at`,
		k.UserID, k.TenantID, k.ProviderKey, k.Name, k.FieldsCipher, k.Kind, k.Description, k.BaseURL, k.DocsURL, k.HeaderName, k.Prefix, k.Username,
	).Scan(&k.ID, &k.CreatedAt)
}

func (p *Postgres) UpdateAPIKey(ctx context.Context, k *APIKey) error {
	_, err := p.pool.Exec(ctx, `
		UPDATE vault.api_keys SET fields_cipher=$3, kind=$4, description=$5, base_url=$6, docs_url=$7,
			header_name=$8, prefix=$9, username=$10, updated_at=now()
		WHERE user_id=$1 AND id=$2`,
		k.UserID, k.ID, k.FieldsCipher, k.Kind, k.Description, k.BaseURL, k.DocsURL, k.HeaderName, k.Prefix, k.Username)
	return err
}

func (p *Postgres) ListAPIKeys(ctx context.Context, userID uuid.UUID) ([]APIKey, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+apiKeyCols+` FROM vault.api_keys WHERE user_id=$1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKey
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

func (p *Postgres) GetAPIKeyByName(ctx context.Context, userID uuid.UUID, name string) (*APIKey, error) {
	k, err := scanAPIKey(p.pool.QueryRow(ctx, `SELECT `+apiKeyCols+` FROM vault.api_keys WHERE user_id=$1 AND name=$2`, userID, name))
	if noRows(err) {
		return nil, nil
	}
	return k, err
}

func (p *Postgres) DeleteAPIKey(ctx context.Context, userID, id uuid.UUID) (bool, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM vault.api_keys WHERE user_id=$1 AND id=$2`, userID, id)
	return tag.RowsAffected() > 0, err
}

func (p *Postgres) TouchAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error {
	_, err := p.pool.Exec(ctx, `UPDATE vault.api_keys SET last_used_at=now() WHERE id=$1`, id)
	return err
}

// ---- oauth provider configs ----

const configCols = `id, user_id, tenant_id, provider_id, provider_key, client_id_cipher, client_secret_cipher, scopes_json, redirect_uri, created_at, updated_at`

func scanConfig(row pgx.Row) (*OAuthProviderConfig, error) {
	var c OAuthProviderConfig
	err := row.Scan(&c.ID, &c.UserID, &c.TenantID, &c.ProviderID, &c.ProviderKey, &c.ClientIDCipher,
		&c.ClientSecretCipher, &c.ScopesJSON, &c.RedirectURI, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (p *Postgres) InsertOAuthConfig(ctx context.Context, c *OAuthProviderConfig) error {
	return p.pool.QueryRow(ctx, `
		INSERT INTO vault.oauth_provider_configs (user_id, tenant_id, provider_id, provider_key, client_id_cipher, client_secret_cipher, scopes_json, redirect_uri)
		VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8) RETURNING id, created_at`,
		c.UserID, c.TenantID, c.ProviderID, c.ProviderKey, c.ClientIDCipher, c.ClientSecretCipher, c.ScopesJSON, c.RedirectURI,
	).Scan(&c.ID, &c.CreatedAt)
}

func (p *Postgres) UpdateOAuthConfig(ctx context.Context, c *OAuthProviderConfig) error {
	_, err := p.pool.Exec(ctx, `
		UPDATE vault.oauth_provider_configs SET provider_key=$3, client_id_cipher=$4, client_secret_cipher=$5,
			scopes_json=$6::jsonb, redirect_uri=$7, updated_at=now()
		WHERE user_id=$1 AND id=$2`,
		c.UserID, c.ID, c.ProviderKey, c.ClientIDCipher, c.ClientSecretCipher, c.ScopesJSON, c.RedirectURI)
	return err
}

func (p *Postgres) ListOAuthConfigs(ctx context.Context, userID uuid.UUID) ([]OAuthProviderConfig, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+configCols+` FROM vault.oauth_provider_configs WHERE user_id=$1 ORDER BY provider_key`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OAuthProviderConfig
	for rows.Next() {
		c, err := scanConfig(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

func (p *Postgres) GetOAuthConfigByProvider(ctx context.Context, userID, providerID uuid.UUID) (*OAuthProviderConfig, error) {
	c, err := scanConfig(p.pool.QueryRow(ctx, `SELECT `+configCols+` FROM vault.oauth_provider_configs WHERE user_id=$1 AND provider_id=$2`, userID, providerID))
	if noRows(err) {
		return nil, nil
	}
	return c, err
}

func (p *Postgres) DeleteOAuthConfig(ctx context.Context, userID, id uuid.UUID) (bool, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM vault.oauth_provider_configs WHERE user_id=$1 AND id=$2`, userID, id)
	return tag.RowsAffected() > 0, err
}

// ---- oauth states ----

func (p *Postgres) InsertOAuthState(ctx context.Context, s *OAuthState) error {
	return p.pool.QueryRow(ctx, `
		INSERT INTO vault.oauth_states (state, provider, code_verifier, owner_user_id, owner_tenant_id, redirect_uri, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, created_at`,
		s.State, s.Provider, s.CodeVerifier, s.OwnerUserID, s.OwnerTenantID, s.RedirectURI, s.ExpiresAt,
	).Scan(&s.ID, &s.CreatedAt)
}

func (p *Postgres) GetOAuthStateByState(ctx context.Context, state string) (*OAuthState, error) {
	var s OAuthState
	err := p.pool.QueryRow(ctx, `
		SELECT id, state, provider, code_verifier, owner_user_id, owner_tenant_id, redirect_uri, expires_at, created_at
		FROM vault.oauth_states WHERE state=$1`, state).
		Scan(&s.ID, &s.State, &s.Provider, &s.CodeVerifier, &s.OwnerUserID, &s.OwnerTenantID, &s.RedirectURI, &s.ExpiresAt, &s.CreatedAt)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (p *Postgres) DeleteOAuthState(ctx context.Context, id uuid.UUID) (int64, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM vault.oauth_states WHERE id=$1`, id)
	return tag.RowsAffected(), err
}

// ---- oauth tokens ----

const tokenCols = `id, user_id, tenant_id, provider_id, provider_key, account, access_token_cipher, refresh_token_cipher, scopes_json, expires_at, last_refreshed_at, created_at, updated_at`

func scanToken(row pgx.Row) (*OAuthToken, error) {
	var t OAuthToken
	err := row.Scan(&t.ID, &t.UserID, &t.TenantID, &t.ProviderID, &t.ProviderKey, &t.Account,
		&t.AccessTokenCipher, &t.RefreshTokenCipher, &t.ScopesJSON, &t.ExpiresAt, &t.LastRefreshedAt, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (p *Postgres) InsertOAuthToken(ctx context.Context, t *OAuthToken) error {
	return p.pool.QueryRow(ctx, `
		INSERT INTO vault.oauth_tokens (user_id, tenant_id, provider_id, provider_key, account, access_token_cipher, refresh_token_cipher, scopes_json, expires_at, last_refreshed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10) RETURNING id, created_at`,
		t.UserID, t.TenantID, t.ProviderID, t.ProviderKey, t.Account, t.AccessTokenCipher, t.RefreshTokenCipher, t.ScopesJSON, t.ExpiresAt, t.LastRefreshedAt,
	).Scan(&t.ID, &t.CreatedAt)
}

func (p *Postgres) UpdateOAuthToken(ctx context.Context, t *OAuthToken) error {
	_, err := p.pool.Exec(ctx, `
		UPDATE vault.oauth_tokens SET access_token_cipher=$2, refresh_token_cipher=$3, scopes_json=$4::jsonb,
			expires_at=$5, last_refreshed_at=$6, updated_at=now()
		WHERE id=$1`,
		t.ID, t.AccessTokenCipher, t.RefreshTokenCipher, t.ScopesJSON, t.ExpiresAt, t.LastRefreshedAt)
	return err
}

func (p *Postgres) ListOAuthTokens(ctx context.Context, userID uuid.UUID) ([]OAuthToken, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+tokenCols+` FROM vault.oauth_tokens WHERE user_id=$1 ORDER BY provider_key`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OAuthToken
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

func (p *Postgres) GetOAuthTokenByID(ctx context.Context, userID, id uuid.UUID) (*OAuthToken, error) {
	t, err := scanToken(p.pool.QueryRow(ctx, `SELECT `+tokenCols+` FROM vault.oauth_tokens WHERE user_id=$1 AND id=$2`, userID, id))
	if noRows(err) {
		return nil, nil
	}
	return t, err
}

func (p *Postgres) FindOAuthToken(ctx context.Context, userID, providerID uuid.UUID, account string) (*OAuthToken, error) {
	q := `SELECT ` + tokenCols + ` FROM vault.oauth_tokens WHERE user_id=$1 AND provider_id=$2`
	args := []any{userID, providerID}
	if account != "" {
		q += ` AND account=$3`
		args = append(args, account)
	}
	q += ` ORDER BY created_at DESC LIMIT 1`
	t, err := scanToken(p.pool.QueryRow(ctx, q, args...))
	if noRows(err) {
		return nil, nil
	}
	return t, err
}

func (p *Postgres) DeleteOAuthToken(ctx context.Context, userID, id uuid.UUID) (bool, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM vault.oauth_tokens WHERE user_id=$1 AND id=$2`, userID, id)
	return tag.RowsAffected() > 0, err
}

// ---- provider manifests ----

const manifestCols = `id, user_id, tenant_id, kind, key, provider_id, parent_id, document_json, created_at, updated_at`

func scanManifest(row pgx.Row) (*ProviderManifest, error) {
	var m ProviderManifest
	err := row.Scan(&m.ID, &m.UserID, &m.TenantID, &m.Kind, &m.Key, &m.ProviderID, &m.ParentID, &m.DocumentJSON, &m.CreatedAt, &m.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (p *Postgres) ListOAuthManifests(ctx context.Context, userID uuid.UUID) ([]ProviderManifest, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+manifestCols+` FROM vault.provider_manifests WHERE kind='oauth' AND user_id=$1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProviderManifest
	for rows.Next() {
		m, err := scanManifest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

func (p *Postgres) GetManifestByKey(ctx context.Context, ownerUserID uuid.UUID, kind, key string) (*ProviderManifest, error) {
	m, err := scanManifest(p.pool.QueryRow(ctx, `SELECT `+manifestCols+` FROM vault.provider_manifests WHERE kind=$1 AND key=$2 AND user_id=$3`, kind, key, ownerUserID))
	if noRows(err) {
		return nil, nil
	}
	return m, err
}

func (p *Postgres) InsertManifest(ctx context.Context, m *ProviderManifest) error {
	return p.pool.QueryRow(ctx, `
		INSERT INTO vault.provider_manifests (user_id, tenant_id, kind, key, provider_id, parent_id, document_json)
		VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb) RETURNING id, created_at`,
		m.UserID, m.TenantID, m.Kind, m.Key, m.ProviderID, m.ParentID, m.DocumentJSON,
	).Scan(&m.ID, &m.CreatedAt)
}

func (p *Postgres) UpdateManifest(ctx context.Context, m *ProviderManifest) error {
	_, err := p.pool.Exec(ctx, `
		UPDATE vault.provider_manifests SET provider_id=$3, parent_id=$4, document_json=$5::jsonb, updated_at=now()
		WHERE user_id=$1 AND id=$2`,
		m.UserID, m.ID, m.ProviderID, m.ParentID, m.DocumentJSON)
	return err
}

func (p *Postgres) DeleteManifestCascade(ctx context.Context, userID uuid.UUID, kind, key string) (bool, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)

	var id, providerID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id, provider_id FROM vault.provider_manifests WHERE kind=$1 AND key=$2 AND user_id=$3`, kind, key, userID).
		Scan(&id, &providerID)
	if noRows(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	if kind == "oauth" {
		// provider_id is minted per user, but scope by user_id anyway — no unscoped writes.
		if _, err := tx.Exec(ctx, `DELETE FROM vault.oauth_provider_configs WHERE provider_id=$1 AND user_id=$2`, providerID, userID); err != nil {
			return false, err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM vault.oauth_tokens WHERE provider_id=$1 AND user_id=$2`, providerID, userID); err != nil {
			return false, err
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM vault.provider_manifests WHERE id=$1`, id); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// ---- audit ----

func (p *Postgres) InsertAuditBatch(ctx context.Context, entries []AuditEntry) error {
	if len(entries) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, e := range entries {
		batch.Queue(`
			INSERT INTO vault.audit_log (event_type, outcome, user_id, tenant_id, access_key_id, access_key_prefix, access_key_name,
				source_ip, headers, target_kind, target_provider, target_account, target_name, transport, method, detail, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8::inet,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
			e.EventType, e.Outcome, e.UserID, e.TenantID, e.AccessKeyID, e.AccessKeyPrefix, e.AccessKeyName,
			e.SourceIP, e.Headers, e.TargetKind, e.TargetProvider, e.TargetAccount, e.TargetName, e.Transport, e.Method, e.Detail, e.CreatedAt)
	}
	br := p.pool.SendBatch(ctx, batch)
	defer br.Close()
	for range entries {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

func (p *Postgres) QueryAudit(ctx context.Context, f AuditFilter) ([]AuditEntry, int, error) {
	where := ` WHERE user_id=$1 AND tenant_id=$2`
	args := []any{f.UserID, f.TenantID}
	add := func(clause string, v any) {
		args = append(args, v)
		where += fmt.Sprintf(clause, len(args))
	}
	if f.EventType != nil {
		add(` AND event_type=$%d`, *f.EventType)
	}
	if f.Outcome != nil {
		add(` AND outcome=$%d`, *f.Outcome)
	}
	if f.FilterUserID != nil {
		add(` AND user_id=$%d`, *f.FilterUserID)
	}
	if f.Since != nil {
		add(` AND created_at>=$%d`, *f.Since)
	}
	if f.Until != nil {
		add(` AND created_at<$%d`, *f.Until)
	}

	var total int
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FROM vault.audit_log`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	q := `SELECT id, event_type, outcome, user_id, tenant_id, access_key_prefix, access_key_name, host(source_ip),
		target_kind, target_provider, target_account, target_name, transport, method, detail, created_at
		FROM vault.audit_log` + where + fmt.Sprintf(` ORDER BY created_at DESC OFFSET $%d LIMIT $%d`, len(args)+1, len(args)+2)
	args = append(args, f.Offset, f.Limit)

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.EventType, &e.Outcome, &e.UserID, &e.TenantID, &e.AccessKeyPrefix, &e.AccessKeyName,
			&e.SourceIP, &e.TargetKind, &e.TargetProvider, &e.TargetAccount, &e.TargetName, &e.Transport, &e.Method, &e.Detail, &e.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

func (p *Postgres) DeleteAuditOlderThan(ctx context.Context, cutoff time.Time, batchSize int) (int64, error) {
	tag, err := p.pool.Exec(ctx, `
		DELETE FROM vault.audit_log WHERE id IN (
			SELECT id FROM vault.audit_log WHERE created_at < $1 ORDER BY created_at LIMIT $2)`, cutoff, batchSize)
	return tag.RowsAffected(), err
}
