using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Contracts.Audit;
using DonkeyWork.Vault.Core.Audit;
using DonkeyWork.Vault.Persistence;
using DonkeyWork.Vault.Persistence.Entities;
using Microsoft.EntityFrameworkCore;
using Testcontainers.PostgreSql;
using Xunit;

namespace DonkeyWork.Vault.Integration.Tests;

[Trait("Category", "Integration")]
public sealed class AuditQueryServiceTests : IAsyncLifetime
{
    private readonly PostgreSqlContainer _pg = new PostgreSqlBuilder().WithImage("postgres:17").WithDatabase("donkeywork_vault").Build();

    public Task InitializeAsync() => _pg.StartAsync();
    public Task DisposeAsync() => _pg.DisposeAsync().AsTask();

    private sealed class FixedCaller(Guid userId, Guid tenantId) : IVaultCallerContext
    {
        public Guid UserId => userId;
        public Guid TenantId => tenantId;
    }

    private async Task<(VaultDbContext db, AuditQueryService svc)> BuildAsync(IVaultCallerContext caller)
    {
        var options = new DbContextOptionsBuilder<VaultDbContext>()
            .UseNpgsql(_pg.GetConnectionString(), n => n.MigrationsHistoryTable("__ef_migrations_history", "vault"))
            .Options;
        var db = new VaultDbContext(options, caller);
        await db.Database.MigrateAsync();

        var (audit, _) = TestAudit.Build(caller);
        return (db, new AuditQueryService(db, audit, caller));
    }

    [Fact]
    public async Task Query_IsScopedToAmbientCaller()
    {
        var tenant = Guid.NewGuid();
        var alice = Guid.NewGuid();
        var bob = Guid.NewGuid();

        var (dbA, _) = await BuildAsync(new FixedCaller(alice, tenant));
        await using (dbA)
        {
            dbA.AuditLogs.AddRange(
                Row(alice, tenant, "alice-token", DateTimeOffset.UtcNow.AddMinutes(-1)),
                Row(bob, tenant, "bob-token", DateTimeOffset.UtcNow));
            await dbA.SaveChangesAsync();
        }

        var (dbB, svcB) = await BuildAsync(new FixedCaller(bob, tenant));
        await using (dbB)
        {
            var result = await svcB.QueryAsync(new AuditQuery(UserId: alice), default);

            Assert.Empty(result.Items);
            Assert.Equal(0, result.Total);
        }

        var (dbB2, svcB2) = await BuildAsync(new FixedCaller(bob, tenant));
        await using (dbB2)
        {
            var result = await svcB2.QueryAsync(new AuditQuery(), default);
            var row = Assert.Single(result.Items);

            Assert.Equal(bob, row.UserId);
            Assert.Equal("bob-token", row.TargetName);
        }
    }

    private static AuditLogEntity Row(Guid userId, Guid tenantId, string targetName, DateTimeOffset createdAt) => new()
    {
        EventType = (int)AuditEventType.TokenAccessed,
        Outcome = (int)AuditOutcome.Success,
        UserId = userId,
        TenantId = tenantId,
        Headers = new Dictionary<string, string>(),
        TargetKind = "oauth_token",
        TargetName = targetName,
        Transport = "http",
        CreatedAt = createdAt,
    };
}
