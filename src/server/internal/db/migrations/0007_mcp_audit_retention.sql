CREATE INDEX IF NOT EXISTS ix_mcp_audit_exchanges_completed_id
    ON vault.mcp_audit_exchanges (completed_at, id) WHERE completed_at IS NOT NULL;
