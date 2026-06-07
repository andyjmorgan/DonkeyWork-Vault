using System.Text;
using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Core.Crypto;
using DonkeyWork.Vault.Core.Manifests;
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
    private readonly PostgreSqlContainer _pg = new PostgreSqlBuilder()
        .WithImage("postgres:17")
        .WithDatabase("donkeywork_vault")
        .Build();

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
            ActiveKekId = "local:v1",
            Keks = new() { ["local:v1"] = Convert.ToBase64String(Enumerable.Repeat((byte)7, 32).ToArray()) },
        })));

        var resolver = new ManifestResolver(db, new ApiKeyManifestLoader(), new OAuthManifestLoader());
        return (db, new ApiKeyService(db, cipher, resolver, caller));
    }

    [Fact]
    public async Task CreateThenGet_RoundTrips_AndStoresCiphertext()
    {
        var caller = new FixedCaller(Guid.NewGuid());
        var (db, svc) = await BuildAsync(caller);
        await using var _ = db;

        var created = await svc.CreateAsync("grafana", "prod",
            new Dictionary<string, string> { ["api_key"] = "secret-123" }, default);
        Assert.NotEqual(Guid.Empty, created.Id);

        // The persisted blob must not contain the plaintext secret.
        var raw = await db.ApiKeys.AsNoTracking().FirstAsync();
        Assert.DoesNotContain("secret-123", Encoding.UTF8.GetString(raw.FieldsCipher));

        var got = await svc.GetAsync("grafana", null, default);
        Assert.NotNull(got);
        Assert.Equal("secret-123", got!.Secret);

        var shape = await svc.DescribeShapeAsync("grafana", default);
        Assert.Equal("Authorization", shape!.Auth.Header);
        Assert.Equal("Bearer ", shape.Auth.Prefix);
    }

    [Fact]
    public async Task Create_MissingRequiredField_Throws()
    {
        var caller = new FixedCaller(Guid.NewGuid());
        var (db, svc) = await BuildAsync(caller);
        await using var _ = db;

        await Assert.ThrowsAsync<CredentialValidationException>(() =>
            svc.CreateAsync("grafana", "prod", new Dictionary<string, string>(), default));
    }

    [Fact]
    public async Task Create_UnknownProvider_Throws()
    {
        var caller = new FixedCaller(Guid.NewGuid());
        var (db, svc) = await BuildAsync(caller);
        await using var _ = db;

        await Assert.ThrowsAsync<ManifestNotFoundException>(() =>
            svc.CreateAsync("does-not-exist", "x",
                new Dictionary<string, string> { ["api_key"] = "v" }, default));
    }

    [Fact]
    public async Task Get_IsScopedToCaller()
    {
        var owner = new FixedCaller(Guid.NewGuid());
        var (db1, svc1) = await BuildAsync(owner);
        await using (db1)
        {
            await svc1.CreateAsync("openai", "k", new Dictionary<string, string> { ["api_key"] = "owned" }, default);
        }

        // A different user shares the DB but must not see the owner's row (query filter).
        var other = new FixedCaller(Guid.NewGuid());
        var (db2, svc2) = await BuildAsync(other);
        await using (db2)
        {
            var got = await svc2.GetAsync("openai", null, default);
            Assert.Null(got);
        }
    }
}
