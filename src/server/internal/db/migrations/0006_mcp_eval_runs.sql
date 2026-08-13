CREATE TABLE IF NOT EXISTS vault.mcp_eval_runs (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL,
    tenant_id     uuid NOT NULL,
    run_id        varchar(255) NOT NULL CHECK (length(btrim(run_id)) > 0),
    access_key_id uuid NOT NULL REFERENCES vault.access_keys(id) ON DELETE CASCADE,
    expires_at    timestamptz NOT NULL,
    revoked_at    timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    CHECK (expires_at > created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_mcp_eval_runs_user_run
    ON vault.mcp_eval_runs (user_id, run_id);
CREATE UNIQUE INDEX IF NOT EXISTS ix_mcp_eval_runs_access_key
    ON vault.mcp_eval_runs (access_key_id);
CREATE INDEX IF NOT EXISTS ix_mcp_eval_runs_tenant_user_created
    ON vault.mcp_eval_runs (tenant_id, user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_mcp_eval_runs_active_expiry
    ON vault.mcp_eval_runs (expires_at) WHERE revoked_at IS NULL;
