using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace DonkeyWork.Vault.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class ApiKeySelfDescribing : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_api_keys_user_id_provider_key_name",
                schema: "vault",
                table: "api_keys");

            migrationBuilder.AddColumn<string>(
                name: "base_url",
                schema: "vault",
                table: "api_keys",
                type: "character varying(512)",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "description",
                schema: "vault",
                table: "api_keys",
                type: "character varying(1024)",
                maxLength: 1024,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "docs_url",
                schema: "vault",
                table: "api_keys",
                type: "character varying(512)",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "header_name",
                schema: "vault",
                table: "api_keys",
                type: "character varying(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "prefix",
                schema: "vault",
                table: "api_keys",
                type: "character varying(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_api_keys_user_id_name",
                schema: "vault",
                table: "api_keys",
                columns: new[] { "user_id", "name" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_api_keys_user_id_name",
                schema: "vault",
                table: "api_keys");

            migrationBuilder.DropColumn(
                name: "base_url",
                schema: "vault",
                table: "api_keys");

            migrationBuilder.DropColumn(
                name: "description",
                schema: "vault",
                table: "api_keys");

            migrationBuilder.DropColumn(
                name: "docs_url",
                schema: "vault",
                table: "api_keys");

            migrationBuilder.DropColumn(
                name: "header_name",
                schema: "vault",
                table: "api_keys");

            migrationBuilder.DropColumn(
                name: "prefix",
                schema: "vault",
                table: "api_keys");

            migrationBuilder.CreateIndex(
                name: "IX_api_keys_user_id_provider_key_name",
                schema: "vault",
                table: "api_keys",
                columns: new[] { "user_id", "provider_key", "name" },
                unique: true);
        }
    }
}
