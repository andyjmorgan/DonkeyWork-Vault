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

            // Resolution is now row-only: the YAML library is never a fallback. Built-in configs/tokens
            // that have no backing provider row (Google/MS/GitHub were never rows) can no longer resolve,
            // so drop those orphans. Providers that ARE rows (e.g. a custom Dropbox) keep their creds.
            // Re-add the built-ins from the library and re-enter their (backed-up) secrets.
            migrationBuilder.Sql(@"
                DELETE FROM vault.oauth_tokens t
                  WHERE NOT EXISTS (SELECT 1 FROM vault.provider_manifests pm
                                    WHERE pm.kind='oauth' AND pm.provider_id = t.provider_id AND pm.user_id = t.user_id);
                DELETE FROM vault.oauth_provider_configs c
                  WHERE NOT EXISTS (SELECT 1 FROM vault.provider_manifests pm
                                    WHERE pm.kind='oauth' AND pm.provider_id = c.provider_id AND pm.user_id = c.user_id);");
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
