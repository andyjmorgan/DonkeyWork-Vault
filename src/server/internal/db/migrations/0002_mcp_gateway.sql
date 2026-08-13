ALTER TABLE vault.access_keys
    ADD COLUMN IF NOT EXISTS expires_at timestamptz;
CREATE INDEX IF NOT EXISTS ix_access_keys_expires ON vault.access_keys (expires_at)
    WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS vault.mcp_connections (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          uuid NOT NULL,
    tenant_id        uuid NOT NULL,
    slug             varchar(100) NOT NULL,
    name             varchar(255) NOT NULL,
    description      varchar(1024),
    upstream_url     text NOT NULL,
    auth_mode        varchar(32) NOT NULL,
    audit_mode       varchar(32) NOT NULL DEFAULT 'redacted',
    protocol_version varchar(32) NOT NULL DEFAULT '2026-07-28',
    enabled          boolean NOT NULL DEFAULT true,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_mcp_connections_user_slug
    ON vault.mcp_connections (user_id, slug);
CREATE INDEX IF NOT EXISTS ix_mcp_connections_tenant_user
    ON vault.mcp_connections (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS vault.mcp_connection_grants (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL,
    tenant_id     uuid NOT NULL,
    connection_id uuid NOT NULL REFERENCES vault.mcp_connections(id) ON DELETE CASCADE,
    access_key_id uuid NOT NULL REFERENCES vault.access_keys(id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_mcp_grants_connection_access_key
    ON vault.mcp_connection_grants (connection_id, access_key_id);
CREATE INDEX IF NOT EXISTS ix_mcp_grants_tenant_user
    ON vault.mcp_connection_grants (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS vault.mcp_header_bindings (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL,
    tenant_id     uuid NOT NULL,
    connection_id uuid NOT NULL REFERENCES vault.mcp_connections(id) ON DELETE CASCADE,
    credential_id uuid NOT NULL REFERENCES vault.api_keys(id) ON DELETE CASCADE,
    header_name   varchar(100),
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_mcp_headers_connection_credential_name
    ON vault.mcp_header_bindings (connection_id, credential_id, coalesce(header_name, ''));
CREATE INDEX IF NOT EXISTS ix_mcp_headers_tenant_user
    ON vault.mcp_header_bindings (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS vault.mcp_tool_policies (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL,
    tenant_id     uuid NOT NULL,
    connection_id uuid NOT NULL REFERENCES vault.mcp_connections(id) ON DELETE CASCADE,
    method        varchar(255) NOT NULL,
    tool_name     varchar(255) NOT NULL DEFAULT '',
    allow         boolean NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_mcp_tool_policies_connection_method_tool
    ON vault.mcp_tool_policies (connection_id, method, tool_name);
CREATE INDEX IF NOT EXISTS ix_mcp_tool_policies_tenant_user
    ON vault.mcp_tool_policies (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS vault.mcp_oauth_authorizations (
    id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                uuid NOT NULL,
    tenant_id              uuid NOT NULL,
    connection_id          uuid NOT NULL REFERENCES vault.mcp_connections(id) ON DELETE CASCADE,
    issuer_url             text,
    authorization_endpoint text,
    token_endpoint         text,
    resource               text,
    token_type             varchar(32),
    token_auth_method      varchar(64) NOT NULL DEFAULT 'none',
    client_id_cipher       bytea NOT NULL DEFAULT ''::bytea,
    client_secret_cipher   bytea NOT NULL DEFAULT ''::bytea,
    access_token_cipher    bytea NOT NULL DEFAULT ''::bytea,
    refresh_token_cipher   bytea NOT NULL DEFAULT ''::bytea,
    scopes                 text[] NOT NULL DEFAULT '{}',
    expires_at             timestamptz,
    last_refreshed_at      timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_mcp_oauth_connection
    ON vault.mcp_oauth_authorizations (connection_id);
CREATE INDEX IF NOT EXISTS ix_mcp_oauth_expires
    ON vault.mcp_oauth_authorizations (expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS vault.mcp_oauth_states (
    state             varchar(128) PRIMARY KEY,
    connection_id     uuid NOT NULL REFERENCES vault.mcp_connections(id) ON DELETE CASCADE,
    user_id           uuid NOT NULL,
    tenant_id         uuid NOT NULL,
    code_verifier     varchar(256) NOT NULL,
    redirect_uri      text NOT NULL,
    resource          text NOT NULL,
    issuer_url        text NOT NULL,
    auth_endpoint     text NOT NULL,
    token_endpoint    text NOT NULL,
    token_auth_method varchar(64) NOT NULL,
    scopes            text[] NOT NULL DEFAULT '{}',
    expires_at        timestamptz NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_mcp_oauth_states_expires
    ON vault.mcp_oauth_states (expires_at);

-- Audit rows deliberately do not reference mutable configuration with foreign keys. Deleting an
-- access key or connection must not erase the record of how it was used.
CREATE TABLE IF NOT EXISTS vault.mcp_audit_exchanges (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id         uuid NOT NULL,
    user_id               uuid NOT NULL,
    tenant_id             uuid NOT NULL,
    access_key_id         uuid NOT NULL,
    eval_run_id           varchar(255),
    downstream_request_id varchar(255),
    upstream_request_id   varchar(255),
    remote_address        varchar(255),
    user_agent            varchar(1024),
    trace_id              varchar(255),
    error_class           varchar(255),
    http_method           varchar(16) NOT NULL,
    protocol_version      varchar(32) NOT NULL,
    outcome               varchar(32) NOT NULL,
    started_at            timestamptz NOT NULL DEFAULT now(),
    completed_at          timestamptz,
    status_code           integer,
    request_bytes         bigint NOT NULL DEFAULT 0,
    response_bytes        bigint NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_mcp_audit_exchanges_owner_started
    ON vault.mcp_audit_exchanges (tenant_id, user_id, started_at DESC);
CREATE INDEX IF NOT EXISTS ix_mcp_audit_exchanges_connection_started
    ON vault.mcp_audit_exchanges (connection_id, started_at DESC);
CREATE INDEX IF NOT EXISTS ix_mcp_audit_exchanges_access_key_started
    ON vault.mcp_audit_exchanges (access_key_id, started_at DESC);
CREATE INDEX IF NOT EXISTS ix_mcp_audit_exchanges_eval_run_started
    ON vault.mcp_audit_exchanges (eval_run_id, started_at DESC) WHERE eval_run_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS vault.mcp_audit_messages (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    exchange_id          uuid NOT NULL REFERENCES vault.mcp_audit_exchanges(id) ON DELETE CASCADE,
    connection_id        uuid NOT NULL,
    user_id              uuid NOT NULL,
    tenant_id            uuid NOT NULL,
    sequence_no          bigint NOT NULL,
    observed_at          timestamptz NOT NULL DEFAULT now(),
    direction            varchar(32) NOT NULL,
    message_kind         varchar(32) NOT NULL,
    policy_decision      varchar(32) NOT NULL,
    jsonrpc_id_type      varchar(16),
    jsonrpc_id_text      text,
    method               varchar(255),
    tool_name            varchar(255),
    policy_rule          varchar(255),
    result_type          varchar(64),
    subscription_id      varchar(255),
    error_code           integer,
    request_state_digest bytea,
    payload_redacted     jsonb,
    payload_sha256       bytea NOT NULL,
    payload_bytes        bigint NOT NULL,
    payload_truncated    boolean NOT NULL DEFAULT false,
    redaction_paths      text[] NOT NULL DEFAULT '{}'
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_mcp_audit_messages_exchange_sequence
    ON vault.mcp_audit_messages (exchange_id, sequence_no);
CREATE INDEX IF NOT EXISTS ix_mcp_audit_messages_owner_observed
    ON vault.mcp_audit_messages (tenant_id, user_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS ix_mcp_audit_messages_connection_observed
    ON vault.mcp_audit_messages (connection_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS ix_mcp_audit_messages_tool_observed
    ON vault.mcp_audit_messages (tool_name, observed_at DESC) WHERE tool_name IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_mcp_audit_messages_decision_observed
    ON vault.mcp_audit_messages (policy_decision, observed_at DESC);
