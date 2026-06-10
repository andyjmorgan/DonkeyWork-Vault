using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace DonkeyWork.Vault.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class OAuthProviderParentId : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "parent_id",
                schema: "vault",
                table: "provider_manifests",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            // Clean OAuth cut-over to the library model: drop all existing OAuth providers, configs and
            // tokens. Resolution is now row-only (the YAML library is never a fallback), so the prior
            // built-in tokens couldn't resolve anyway. Re-add every provider from the library / as custom
            // and re-enter their (backed-up) secrets, then reconnect.
            migrationBuilder.Sql(@"
                DELETE FROM vault.oauth_tokens;
                DELETE FROM vault.oauth_provider_configs;
                DELETE FROM vault.provider_manifests WHERE kind = 'oauth';");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "parent_id",
                schema: "vault",
                table: "provider_manifests");
        }
    }
}
