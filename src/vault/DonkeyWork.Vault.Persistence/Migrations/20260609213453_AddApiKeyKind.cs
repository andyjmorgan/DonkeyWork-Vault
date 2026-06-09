using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace DonkeyWork.Vault.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddApiKeyKind : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "kind",
                schema: "vault",
                table: "api_keys",
                type: "character varying(32)",
                maxLength: 32,
                nullable: false,
                defaultValue: "opaque");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "kind",
                schema: "vault",
                table: "api_keys");
        }
    }
}
