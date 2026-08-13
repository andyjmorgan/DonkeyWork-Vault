-- A new authorization attempt supersedes every earlier attempt for the same connection. Preserve
-- the newest legacy row before adding the cross-replica invariant.
WITH ranked AS (
    SELECT state,
           row_number() OVER (
               PARTITION BY connection_id
               ORDER BY created_at DESC, state DESC
           ) AS position
    FROM vault.mcp_oauth_states
)
DELETE FROM vault.mcp_oauth_states states
USING ranked
WHERE states.state = ranked.state
  AND ranked.position > 1;

CREATE UNIQUE INDEX IF NOT EXISTS ix_mcp_oauth_states_connection
    ON vault.mcp_oauth_states (connection_id);
