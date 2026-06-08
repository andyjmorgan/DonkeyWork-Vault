using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace DonkeyWork.Vault.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddApiKeyUsername : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Non-secret. When set, the credential is HTTP Basic auth and is sent as
            // Authorization: Basic base64(username:password). Additive + nullable, so
            // existing rows keep behaving as bearer/header credentials.
            migrationBuilder.AddColumn<string>(
                name: "username",
                schema: "vault",
                table: "api_keys",
                type: "character varying(255)",
                maxLength: 255,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "username",
                schema: "vault",
                table: "api_keys");
        }
    }
}
