using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace DonkeyWork.Vault.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class ScopeManifestsToUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Custom manifests become per-user (user_id, NOT NULL). Existing rows were globally
            // shared and have no owner, so drop them rather than assign them to the empty guid.
            migrationBuilder.Sql("DELETE FROM vault.provider_manifests;");

            migrationBuilder.DropIndex(
                name: "IX_provider_manifests_tenant_id_kind_key",
                schema: "vault",
                table: "provider_manifests");

            migrationBuilder.AddColumn<Guid>(
                name: "user_id",
                schema: "vault",
                table: "provider_manifests",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.CreateIndex(
                name: "IX_provider_manifests_user_id_kind_key",
                schema: "vault",
                table: "provider_manifests",
                columns: new[] { "user_id", "kind", "key" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_provider_manifests_user_id_kind_key",
                schema: "vault",
                table: "provider_manifests");

            migrationBuilder.DropColumn(
                name: "user_id",
                schema: "vault",
                table: "provider_manifests");

            migrationBuilder.CreateIndex(
                name: "IX_provider_manifests_tenant_id_kind_key",
                schema: "vault",
                table: "provider_manifests",
                columns: new[] { "tenant_id", "kind", "key" },
                unique: true);
        }
    }
}
