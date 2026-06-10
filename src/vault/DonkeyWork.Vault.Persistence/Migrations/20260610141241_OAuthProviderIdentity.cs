using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace DonkeyWork.Vault.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class OAuthProviderIdentity : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_oauth_tokens_user_id_provider_key_account",
                schema: "vault",
                table: "oauth_tokens");

            migrationBuilder.DropIndex(
                name: "IX_oauth_provider_configs_user_id_provider_key",
                schema: "vault",
                table: "oauth_provider_configs");

            migrationBuilder.AddColumn<Guid>(
                name: "provider_id",
                schema: "vault",
                table: "provider_manifests",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "provider_id",
                schema: "vault",
                table: "oauth_tokens",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "provider_id",
                schema: "vault",
                table: "oauth_provider_configs",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            // Backfill stable provider identities BEFORE the unique (user_id, provider_id) indexes are
            // built, so existing rows don't collide on the empty default. Built-in templates use the
            // static catalog GUIDs baked into their YAML; custom providers use their own manifest id.
            // This preserves live tokens/configs (no reconnect needed) instead of dropping data.
            migrationBuilder.Sql(@"
                UPDATE vault.provider_manifests SET provider_id = id WHERE kind = 'oauth';
                UPDATE vault.provider_manifests SET provider_id = 'b8cca12c-7524-4523-9190-81409cf25682' WHERE kind='oauth' AND key='google';
                UPDATE vault.provider_manifests SET provider_id = '0f22f7b0-745a-491a-a0db-5091e55c45a7' WHERE kind='oauth' AND key='github';
                UPDATE vault.provider_manifests SET provider_id = '233d6bab-3a4f-4c48-84b4-2e38be309235' WHERE kind='oauth' AND key='microsoft';

                UPDATE vault.oauth_provider_configs SET provider_id = 'b8cca12c-7524-4523-9190-81409cf25682' WHERE provider_key='google';
                UPDATE vault.oauth_provider_configs SET provider_id = '0f22f7b0-745a-491a-a0db-5091e55c45a7' WHERE provider_key='github';
                UPDATE vault.oauth_provider_configs SET provider_id = '233d6bab-3a4f-4c48-84b4-2e38be309235' WHERE provider_key='microsoft';
                UPDATE vault.oauth_provider_configs c SET provider_id = pm.provider_id
                  FROM vault.provider_manifests pm
                  WHERE pm.kind='oauth' AND pm.user_id = c.user_id AND pm.key = c.provider_key
                    AND c.provider_id = '00000000-0000-0000-0000-000000000000';

                UPDATE vault.oauth_tokens SET provider_id = 'b8cca12c-7524-4523-9190-81409cf25682' WHERE provider_key='google';
                UPDATE vault.oauth_tokens SET provider_id = '0f22f7b0-745a-491a-a0db-5091e55c45a7' WHERE provider_key='github';
                UPDATE vault.oauth_tokens SET provider_id = '233d6bab-3a4f-4c48-84b4-2e38be309235' WHERE provider_key='microsoft';
                UPDATE vault.oauth_tokens t SET provider_id = pm.provider_id
                  FROM vault.provider_manifests pm
                  WHERE pm.kind='oauth' AND pm.user_id = t.user_id AND pm.key = t.provider_key
                    AND t.provider_id = '00000000-0000-0000-0000-000000000000';");

            migrationBuilder.CreateIndex(
                name: "IX_provider_manifests_user_id_provider_id",
                schema: "vault",
                table: "provider_manifests",
                columns: new[] { "user_id", "provider_id" });

            migrationBuilder.CreateIndex(
                name: "IX_oauth_tokens_user_id_provider_id_account",
                schema: "vault",
                table: "oauth_tokens",
                columns: new[] { "user_id", "provider_id", "account" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_oauth_provider_configs_user_id_provider_id",
                schema: "vault",
                table: "oauth_provider_configs",
                columns: new[] { "user_id", "provider_id" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_provider_manifests_user_id_provider_id",
                schema: "vault",
                table: "provider_manifests");

            migrationBuilder.DropIndex(
                name: "IX_oauth_tokens_user_id_provider_id_account",
                schema: "vault",
                table: "oauth_tokens");

            migrationBuilder.DropIndex(
                name: "IX_oauth_provider_configs_user_id_provider_id",
                schema: "vault",
                table: "oauth_provider_configs");

            migrationBuilder.DropColumn(
                name: "provider_id",
                schema: "vault",
                table: "provider_manifests");

            migrationBuilder.DropColumn(
                name: "provider_id",
                schema: "vault",
                table: "oauth_tokens");

            migrationBuilder.DropColumn(
                name: "provider_id",
                schema: "vault",
                table: "oauth_provider_configs");

            migrationBuilder.CreateIndex(
                name: "IX_oauth_tokens_user_id_provider_key_account",
                schema: "vault",
                table: "oauth_tokens",
                columns: new[] { "user_id", "provider_key", "account" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_oauth_provider_configs_user_id_provider_key",
                schema: "vault",
                table: "oauth_provider_configs",
                columns: new[] { "user_id", "provider_key" },
                unique: true);
        }
    }
}
