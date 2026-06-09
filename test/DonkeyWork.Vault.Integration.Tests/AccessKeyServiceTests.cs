using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Core.Services;
using DonkeyWork.Vault.Persistence;
using Microsoft.EntityFrameworkCore;
using Testcontainers.PostgreSql;
using Xunit;

namespace DonkeyWork.Vault.Integration.Tests;

[Trait("Category", "Integration")]
public sealed class AccessKeyServiceTests : IAsyncLifetime
{
    private readonly PostgreSqlContainer _pg = new PostgreSqlBuilder().WithImage("postgres:17").WithDatabase("donkeywork_vault").Build();

    public Task InitializeAsync() => _pg.StartAsync();
    public Task DisposeAsync() => _pg.DisposeAsync().AsTask();

    private sealed class FixedCaller(Guid userId) : IVaultCallerContext
    {
        public Guid UserId => userId;
        public Guid TenantId => Guid.Empty;
    }

    private async Task<(VaultDbContext db, AccessKeyService svc)> BuildAsync(IVaultCallerContext caller)
    {
        var options = new DbContextOptionsBuilder<VaultDbContext>()
            .UseNpgsql(_pg.GetConnectionString(), n => n.MigrationsHistoryTable("__ef_migrations_history", "vault"))
            .Options;
        var db = new VaultDbContext(options, caller);
        await db.Database.MigrateAsync();
        var (audit, _) = TestAudit.Build(caller);
        return (db, new AccessKeyService(db, caller, audit));
    }

    [Fact]
    public async Task Create_ReturnsSecretOnce_AndOnlyHashIsStored()
    {
        var (db, svc) = await BuildAsync(new FixedCaller(Guid.NewGuid()));
        await using var _ = db;

        var (key, secret) = await svc.CreateAsync("agent-bot", "ci runner", ["vault:read"], default);

        Assert.StartsWith("dwv_", secret);
        Assert.StartsWith("dwv_", key.Prefix);
        Assert.True(key.Enabled);

        // The plaintext secret must never be persisted — only its SHA-256 hash.
        var raw = await db.AccessKeys.AsNoTracking().FirstAsync();
        Assert.Equal(32, raw.KeyHash.Length);
        Assert.DoesNotContain(secret, System.Text.Encoding.UTF8.GetString(raw.KeyHash));
        Assert.NotEqual(System.Text.Encoding.UTF8.GetBytes(secret), raw.KeyHash);
    }

    [Fact]
    public async Task Authenticate_RoundTrips_OwnerAndScopes()
    {
        var owner = Guid.NewGuid();
        var (db, svc) = await BuildAsync(new FixedCaller(owner));
        await using var _ = db;

        var (_, secret) = await svc.CreateAsync("k", null, ["vault:read", "frontend:readwrite"], default);

        var principal = await svc.AuthenticateAsync(secret, default);
        Assert.NotNull(principal);
        Assert.Equal(owner, principal!.UserId);
        Assert.Contains("vault:read", principal.Scopes);
        Assert.Contains("frontend:readwrite", principal.Scopes);
    }

    [Fact]
    public async Task Authenticate_DisabledKey_ReturnsNull()
    {
        var (db, svc) = await BuildAsync(new FixedCaller(Guid.NewGuid()));
        await using var _ = db;

        var (key, secret) = await svc.CreateAsync("k", null, ["vault:read"], default);
        await svc.SetEnabledAsync(key.Id, false, default);

        Assert.Null(await svc.AuthenticateAsync(secret, default));

        // Re-enabling restores it.
        await svc.SetEnabledAsync(key.Id, true, default);
        Assert.NotNull(await svc.AuthenticateAsync(secret, default));
    }

    [Fact]
    public async Task Authenticate_UnknownSecret_ReturnsNull()
    {
        var (db, svc) = await BuildAsync(new FixedCaller(Guid.NewGuid()));
        await using var _ = db;
        Assert.Null(await svc.AuthenticateAsync("dwv_not-a-real-key", default));
    }

    [Fact]
    public async Task Create_InvalidScope_Throws()
    {
        var (db, svc) = await BuildAsync(new FixedCaller(Guid.NewGuid()));
        await using var _ = db;
        await Assert.ThrowsAsync<CredentialValidationException>(() =>
            svc.CreateAsync("k", null, ["vault:admin"], default));
    }

    [Fact]
    public async Task Create_NoScopes_Throws()
    {
        var (db, svc) = await BuildAsync(new FixedCaller(Guid.NewGuid()));
        await using var _ = db;
        await Assert.ThrowsAsync<CredentialValidationException>(() =>
            svc.CreateAsync("k", null, [], default));
    }

    [Fact]
    public async Task ListAndDelete_AreScopedToCaller()
    {
        var owner = new FixedCaller(Guid.NewGuid());
        Guid id;
        var (db1, svc1) = await BuildAsync(owner);
        await using (db1)
        {
            var (key, _) = await svc1.CreateAsync("mine", null, ["vault:read"], default);
            id = key.Id;
            Assert.Single(await svc1.ListAsync(default));
        }

        var (db2, svc2) = await BuildAsync(new FixedCaller(Guid.NewGuid()));
        await using (db2)
        {
            Assert.Empty(await svc2.ListAsync(default));
            Assert.False(await svc2.DeleteAsync(id, default)); // can't delete another user's key
        }
    }
}
