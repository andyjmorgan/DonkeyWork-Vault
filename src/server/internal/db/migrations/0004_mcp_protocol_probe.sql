ALTER TABLE vault.mcp_connections
    ADD COLUMN IF NOT EXISTS protocol_era varchar(32) NOT NULL DEFAULT 'unknown'
        CHECK (protocol_era IN ('unknown', 'modern_2026_07', 'legacy_session_likely', 'incompatible')),
    ADD COLUMN IF NOT EXISTS probe_status varchar(32) NOT NULL DEFAULT 'not_checked'
        CHECK (probe_status IN ('not_checked', 'compatible', 'incompatible', 'auth_required', 'unreachable', 'error')),
    ADD COLUMN IF NOT EXISTS probe_checked_at timestamptz,
    ADD COLUMN IF NOT EXISTS probe_error varchar(255),
    ADD COLUMN IF NOT EXISTS probe_detail varchar(1024),
    ADD COLUMN IF NOT EXISTS supported_versions text[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS server_name varchar(255),
    ADD COLUMN IF NOT EXISTS server_version varchar(255);

CREATE INDEX IF NOT EXISTS ix_mcp_connections_probe_status
    ON vault.mcp_connections (probe_status, probe_checked_at);
