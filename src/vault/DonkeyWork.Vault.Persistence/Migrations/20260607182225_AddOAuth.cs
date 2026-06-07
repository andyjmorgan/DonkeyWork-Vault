using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace DonkeyWork.Vault.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddOAuth : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "oauth_provider_configs",
                schema: "vault",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    provider_key = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    client_id_cipher = table.Column<byte[]>(type: "bytea", nullable: false),
                    client_secret_cipher = table.Column<byte[]>(type: "bytea", nullable: false),
                    scopes_json = table.Column<string>(type: "jsonb", nullable: true),
                    redirect_uri = table.Column<string>(type: "text", nullable: true),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_oauth_provider_configs", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "oauth_tokens",
                schema: "vault",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    provider_key = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    account = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    access_token_cipher = table.Column<byte[]>(type: "bytea", nullable: false),
                    refresh_token_cipher = table.Column<byte[]>(type: "bytea", nullable: false),
                    scopes_json = table.Column<string>(type: "jsonb", nullable: true),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    last_refreshed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_oauth_tokens", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_oauth_provider_configs_user_id_provider_key",
                schema: "vault",
                table: "oauth_provider_configs",
                columns: new[] { "user_id", "provider_key" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_oauth_tokens_expires_at",
                schema: "vault",
                table: "oauth_tokens",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "IX_oauth_tokens_user_id_provider_key_account",
                schema: "vault",
                table: "oauth_tokens",
                columns: new[] { "user_id", "provider_key", "account" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "oauth_provider_configs",
                schema: "vault");

            migrationBuilder.DropTable(
                name: "oauth_tokens",
                schema: "vault");
        }
    }
}
