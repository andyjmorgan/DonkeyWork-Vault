using System.Text;
using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Core.Crypto;
using DonkeyWork.Vault.Core.Services;
using DonkeyWork.Vault.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Testcontainers.PostgreSql;
using Xunit;

namespace DonkeyWork.Vault.Integration.Tests;

[Trait("Category", "Integration")]
public sealed class ApiKeyServiceTests : IAsyncLifetime
{
    private readonly PostgreSqlContainer _pg = new PostgreSqlBuilder().WithImage("postgres:17").WithDatabase("donkeywork_vault").Build();

    public Task InitializeAsync() => _pg.StartAsync();
    public Task DisposeAsync() => _pg.DisposeAsync().AsTask();

    private sealed class FixedCaller(Guid userId) : IVaultCallerContext
    {
        public Guid UserId => userId;
        public Guid TenantId => Guid.Empty;
    }

    private async Task<(VaultDbContext db, ApiKeyService svc)> BuildAsync(IVaultCallerContext caller)
    {
        var options = new DbContextOptionsBuilder<VaultDbContext>()
            .UseNpgsql(_pg.GetConnectionString(), n => n.MigrationsHistoryTable("__ef_migrations_history", "vault"))
            .Options;
        var db = new VaultDbContext(options, caller);
        await db.Database.MigrateAsync();

        var cipher = new EnvelopeCipherService(new LocalKekProvider(Options.Create(new VaultCryptoOptions
        {
            ActiveKekId = "v1",
            Keks = new() { ["v1"] = Convert.ToBase64String(Enumerable.Repeat((byte)7, 32).ToArray()) },
        })));
        var (audit, _) = TestAudit.Build(caller);
        return (db, new ApiKeyService(db, cipher, caller, audit));
    }

    [Fact]
    public async Task CreateThenGet_RoundTrips_SelfDescribing_AndCiphertextAtRest()
    {
        var (db, svc) = await BuildAsync(new FixedCaller(Guid.NewGuid()));
        await using var _ = db;

        await svc.CreateAsync("grafana", "secret-123", "Grafana prod", "https://grafana.donkeywork.dev",
            "https://grafana.com/docs", "Authorization", "Bearer ", null, CredentialKind.HeaderApiKey, default);

        var raw = await db.ApiKeys.AsNoTracking().FirstAsync();
        Assert.DoesNotContain("secret-123", Encoding.UTF8.GetString(raw.FieldsCipher));

        var got = await svc.GetByNameAsync("grafana", default);
        Assert.NotNull(got);
        Assert.Equal("secret-123", got!.Secret);
        Assert.Equal("Authorization", got.Header);
        Assert.Equal("Bearer ", got.Prefix);
        Assert.Equal("https://grafana.donkeywork.dev", got.BaseUrl);
        Assert.Equal("https://grafana.com/docs", got.DocsUrl);
        Assert.Equal("Grafana prod", got.Description);
    }

    [Fact]
    public async Task Create_MissingSecret_Throws()
    {
        var (db, svc) = await BuildAsync(new FixedCaller(Guid.NewGuid()))
            ;
        await using var _ = db;
        await Assert.ThrowsAsync<CredentialValidationException>(() =>
            svc.CreateAsync("x", "", null, null, null, "Authorization", null, null, CredentialKind.HeaderApiKey, default));
    }

    [Fact]
    public async Task BasicAuth_RoundTrips_AndShapeDescribesUsage()
    {
        var (db, svc) = await BuildAsync(new FixedCaller(Guid.NewGuid()));
        await using var _ = db;

        // username present ⇒ Basic; header defaults to Authorization, prefix is ignored.
        var stored = await svc.CreateAsync("nexus", "hunter2", "Nexus admin", "https://nexus.donkeywork.dev",
            null, null, null, "admin", CredentialKind.HttpBasic, default);
        Assert.Equal("admin", stored.Username);
        Assert.Equal("Authorization", stored.Header);

        var got = await svc.GetByNameAsync("nexus", default);
        Assert.NotNull(got);
        Assert.Equal("hunter2", got!.Secret);
        Assert.Equal("admin", got.Username);

        // The credential describes how to use it: Authorization: Basic base64(user:pass).
        Assert.Equal(CredentialUsage.Basic, CredentialUsage.Scheme(got.Username));
        var (name, value) = CredentialUsage.AssembleHeader(got.Header, got.Prefix, got.Username, got.Secret);
        Assert.Equal("Authorization", name);
        Assert.Equal("Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("admin:hunter2")), value);
    }

    [Fact]
    public async Task BasicAuth_UsernameWithColon_Throws()
    {
        var (db, svc) = await BuildAsync(new FixedCaller(Guid.NewGuid()));
        await using var _ = db;
        await Assert.ThrowsAsync<CredentialValidationException>(() =>
            svc.CreateAsync("x", "pw", null, null, null, null, null, "ad:min", CredentialKind.HttpBasic, default));
    }

    [Fact]
    public async Task BasicAuth_MissingPassword_Throws()
    {
        var (db, svc) = await BuildAsync(new FixedCaller(Guid.NewGuid()));
        await using var _ = db;
        await Assert.ThrowsAsync<CredentialValidationException>(() =>
            svc.CreateAsync("x", "", null, null, null, null, null, "admin", CredentialKind.HttpBasic, default));
    }

    [Fact]
    public async Task Get_IsScopedToCaller()
    {
        var owner = new FixedCaller(Guid.NewGuid());
        var (db1, svc1) = await BuildAsync(owner);
        await using (db1) { await svc1.CreateAsync("svc", "owned", null, null, null, "Authorization", "Bearer ", null, CredentialKind.HeaderApiKey, default); }

        var (db2, svc2) = await BuildAsync(new FixedCaller(Guid.NewGuid()));
        await using (db2) { Assert.Null(await svc2.GetByNameAsync("svc", default)); }
    }
}
