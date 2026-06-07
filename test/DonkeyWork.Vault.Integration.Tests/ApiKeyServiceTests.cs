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
        return (db, new ApiKeyService(db, cipher, caller));
    }

    [Fact]
    public async Task CreateThenGet_RoundTrips_SelfDescribing_AndCiphertextAtRest()
    {
        var (db, svc) = await BuildAsync(new FixedCaller(Guid.NewGuid()));
        await using var _ = db;

        await svc.CreateAsync("grafana", "secret-123", "Grafana prod", "https://grafana.donkeywork.dev",
            "https://grafana.com/docs", "Authorization", "Bearer ", default);

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
            svc.CreateAsync("x", "", null, null, null, "Authorization", null, default));
    }

    [Fact]
    public async Task Get_IsScopedToCaller()
    {
        var owner = new FixedCaller(Guid.NewGuid());
        var (db1, svc1) = await BuildAsync(owner);
        await using (db1) { await svc1.CreateAsync("svc", "owned", null, null, null, "Authorization", "Bearer ", default); }

        var (db2, svc2) = await BuildAsync(new FixedCaller(Guid.NewGuid()));
        await using (db2) { Assert.Null(await svc2.GetByNameAsync("svc", default)); }
    }
}
