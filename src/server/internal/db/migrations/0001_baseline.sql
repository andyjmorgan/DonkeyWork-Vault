-- Baseline schema for the Go vault service.
--
-- This is intentionally idempotent (CREATE ... IF NOT EXISTS): against a database the .NET/EF
-- service already provisioned it is a no-op and every existing row is retained; against a fresh
-- database it creates the full `vault` schema. Column names and types match the EF model snapshot
-- exactly so both services interoperate on the same data.
--
-- The two EF/framework-only tables are dropped: they hold nothing the application reads back
-- (__ef_migrations_history is EF bookkeeping; data_protection_keys backed ASP.NET DataProtection,
-- which was registered but never used to protect any persisted column — the real secret encryption
-- is the envelope cipher).

CREATE SCHEMA IF NOT EXISTS vault;

CREATE TABLE IF NOT EXISTS vault.access_keys (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL,
    tenant_id   uuid NOT NULL,
    name        varchar(255) NOT NULL,
    description varchar(1024),
    key_hash    bytea NOT NULL,
    key_prefix  varchar(32) NOT NULL,
    scopes      text[] NOT NULL,
    enabled     boolean NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz,
    last_used_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_access_keys_key_hash ON vault.access_keys (key_hash);
CREATE INDEX IF NOT EXISTS ix_access_keys_tenant_user ON vault.access_keys (tenant_id, user_id);
CREATE UNIQUE INDEX IF NOT EXISTS ix_access_keys_user_name ON vault.access_keys (user_id, name);

CREATE TABLE IF NOT EXISTS vault.api_keys (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid NOT NULL,
    tenant_id    uuid NOT NULL,
    provider_key varchar(100) NOT NULL,
    name         varchar(255) NOT NULL,
    fields_cipher bytea NOT NULL,
    kind         varchar(32) NOT NULL DEFAULT 'opaque',
    description  varchar(1024),
    base_url     varchar(512),
    docs_url     varchar(512),
    header_name  varchar(100),
    prefix       varchar(100),
    username     varchar(255),
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz,
    last_used_at timestamptz
);
CREATE INDEX IF NOT EXISTS ix_api_keys_tenant_user ON vault.api_keys (tenant_id, user_id);
CREATE UNIQUE INDEX IF NOT EXISTS ix_api_keys_user_name ON vault.api_keys (user_id, name);

CREATE TABLE IF NOT EXISTS vault.oauth_provider_configs (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id              uuid NOT NULL,
    tenant_id            uuid NOT NULL,
    provider_id          uuid NOT NULL,
    provider_key         varchar(100) NOT NULL,
    client_id_cipher     bytea NOT NULL,
    client_secret_cipher bytea NOT NULL,
    scopes_json          jsonb,
    redirect_uri         text,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_oauth_configs_user_provider ON vault.oauth_provider_configs (user_id, provider_id);

CREATE TABLE IF NOT EXISTS vault.oauth_states (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    state           varchar(128) NOT NULL,
    provider        varchar(100) NOT NULL,
    code_verifier   varchar(256) NOT NULL,
    owner_user_id   uuid NOT NULL,
    owner_tenant_id uuid NOT NULL,
    redirect_uri    varchar(512) NOT NULL,
    expires_at      timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_oauth_states_expires ON vault.oauth_states (expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS ix_oauth_states_state ON vault.oauth_states (state);

CREATE TABLE IF NOT EXISTS vault.oauth_tokens (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id              uuid NOT NULL,
    tenant_id            uuid NOT NULL,
    provider_id          uuid NOT NULL,
    provider_key         varchar(100) NOT NULL,
    account              varchar(255) NOT NULL,
    access_token_cipher  bytea NOT NULL,
    refresh_token_cipher bytea NOT NULL,
    scopes_json          jsonb,
    expires_at           timestamptz,
    last_refreshed_at    timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz
);
CREATE INDEX IF NOT EXISTS ix_oauth_tokens_expires ON vault.oauth_tokens (expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS ix_oauth_tokens_user_provider_account ON vault.oauth_tokens (user_id, provider_id, account);

CREATE TABLE IF NOT EXISTS vault.provider_manifests (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL,
    tenant_id     uuid NOT NULL,
    kind          varchar(20) NOT NULL,
    key           varchar(100) NOT NULL,
    provider_id   uuid NOT NULL,
    parent_id     uuid NOT NULL,
    document_json jsonb NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz
);
CREATE INDEX IF NOT EXISTS ix_provider_manifests_user_provider ON vault.provider_manifests (user_id, provider_id);
CREATE UNIQUE INDEX IF NOT EXISTS ix_provider_manifests_user_kind_key ON vault.provider_manifests (user_id, kind, key);

CREATE TABLE IF NOT EXISTS vault.audit_log (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type        integer NOT NULL,
    outcome           integer NOT NULL,
    user_id           uuid NOT NULL,
    tenant_id         uuid NOT NULL,
    access_key_id     uuid,
    access_key_prefix varchar(32),
    access_key_name   varchar(255),
    source_ip         inet,
    headers           jsonb NOT NULL,
    target_kind       varchar(64),
    target_provider   varchar(255),
    target_account    varchar(320),
    target_name       varchar(255),
    transport         varchar(16) NOT NULL,
    method            varchar(255),
    detail            varchar(1024),
    created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_audit_created ON vault.audit_log (created_at);
CREATE INDEX IF NOT EXISTS ix_audit_access_key_created ON vault.audit_log (access_key_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_audit_event_created ON vault.audit_log (event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_audit_tenant_user ON vault.audit_log (tenant_id, user_id);
CREATE INDEX IF NOT EXISTS ix_audit_user_created ON vault.audit_log (user_id, created_at DESC);

-- Drop the EF/framework-only tables (safe: nothing the application reads).
DROP TABLE IF EXISTS vault."__ef_migrations_history";
DROP TABLE IF EXISTS vault.data_protection_keys;
