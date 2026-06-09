using System;
using System.Net;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace DonkeyWork.Vault.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddAuditLog : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "audit_log",
                schema: "vault",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    event_type = table.Column<int>(type: "integer", nullable: false),
                    outcome = table.Column<int>(type: "integer", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    access_key_id = table.Column<Guid>(type: "uuid", nullable: true),
                    access_key_prefix = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    access_key_name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    source_ip = table.Column<IPAddress>(type: "inet", nullable: true),
                    headers = table.Column<string>(type: "jsonb", nullable: false),
                    target_kind = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    target_provider = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    target_account = table.Column<string>(type: "character varying(320)", maxLength: 320, nullable: true),
                    target_name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    transport = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    method = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    detail = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_audit_log", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_audit_log_access_key_id_created_at",
                schema: "vault",
                table: "audit_log",
                columns: new[] { "access_key_id", "created_at" },
                descending: new[] { false, true });

            migrationBuilder.CreateIndex(
                name: "IX_audit_log_created_at",
                schema: "vault",
                table: "audit_log",
                column: "created_at");

            migrationBuilder.CreateIndex(
                name: "IX_audit_log_event_type_created_at",
                schema: "vault",
                table: "audit_log",
                columns: new[] { "event_type", "created_at" },
                descending: new[] { false, true });

            migrationBuilder.CreateIndex(
                name: "IX_audit_log_tenant_id_user_id",
                schema: "vault",
                table: "audit_log",
                columns: new[] { "tenant_id", "user_id" });

            migrationBuilder.CreateIndex(
                name: "IX_audit_log_user_id_created_at",
                schema: "vault",
                table: "audit_log",
                columns: new[] { "user_id", "created_at" },
                descending: new[] { false, true });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "audit_log",
                schema: "vault");
        }
    }
}
