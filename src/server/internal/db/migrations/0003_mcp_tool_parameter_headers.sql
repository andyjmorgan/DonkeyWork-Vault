CREATE TABLE IF NOT EXISTS vault.mcp_tool_parameter_headers (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL,
    tenant_id     uuid NOT NULL,
    connection_id uuid NOT NULL REFERENCES vault.mcp_connections(id) ON DELETE CASCADE,
    tool_name     varchar(255) NOT NULL CHECK (length(btrim(tool_name)) > 0),
    header_name   varchar(255) NOT NULL CHECK (length(btrim(header_name)) > 0),
    argument_path text[] NOT NULL CHECK (cardinality(argument_path) > 0),
    required      boolean NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_mcp_tool_parameter_headers_identity
    ON vault.mcp_tool_parameter_headers (connection_id, tool_name, lower(header_name));
CREATE INDEX IF NOT EXISTS ix_mcp_tool_parameter_headers_lookup
    ON vault.mcp_tool_parameter_headers (user_id, connection_id, tool_name);
