using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace DonkeyWork.Vault.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class RenameFrontendScopesToVault : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Unify the access-key scopes on the vault:* namespace now that the portal's frontend:*
            // scopes are gone. Rewrite stored grants in place so existing keys keep working:
            //   frontend:read      -> vault:read
            //   frontend:readwrite -> vault:readwrite
            migrationBuilder.Sql(
                """
                UPDATE vault.access_keys
                SET scopes = array_replace(
                                 array_replace(scopes, 'frontend:readwrite', 'vault:readwrite'),
                                 'frontend:read', 'vault:read')
                WHERE scopes && ARRAY['frontend:read', 'frontend:readwrite'];
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Best-effort reverse (a natively-minted vault:* key cannot be distinguished from a
            // migrated one, but no vault:* keys existed before this migration).
            migrationBuilder.Sql(
                """
                UPDATE vault.access_keys
                SET scopes = array_replace(
                                 array_replace(scopes, 'vault:readwrite', 'frontend:readwrite'),
                                 'vault:read', 'frontend:read')
                WHERE scopes && ARRAY['vault:read', 'vault:readwrite'];
                """);
        }
    }
}
