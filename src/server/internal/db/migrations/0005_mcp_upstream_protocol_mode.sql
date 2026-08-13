ALTER TABLE vault.mcp_connections
    ADD COLUMN IF NOT EXISTS upstream_protocol_mode varchar(32) NOT NULL DEFAULT 'modern_2026_07'
        CHECK (upstream_protocol_mode IN ('modern_2026_07', 'legacy_session')),
    ADD COLUMN IF NOT EXISTS legacy_protocol_version varchar(10) NOT NULL DEFAULT '2025-06-18'
        CHECK (legacy_protocol_version IN ('2025-03-26', '2025-06-18', '2025-11-25'));
