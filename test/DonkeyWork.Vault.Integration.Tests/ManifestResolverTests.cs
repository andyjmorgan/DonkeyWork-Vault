using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Core.Manifests;
using DonkeyWork.Vault.Persistence;
using DonkeyWork.Vault.Persistence.Entities;
using Microsoft.EntityFrameworkCore;
using Testcontainers.PostgreSql;
using Xunit;

namespace DonkeyWork.Vault.Integration.Tests;

[Trait("Category", "Integration")]
public sealed class ManifestResolverTests : IAsyncLifetime
{
    private readonly PostgreSqlContainer _pg = new PostgreSqlBuilder().WithImage("postgres:17").WithDatabase("donkeywork_vault").Build();
    private readonly OAuthManifestLoader _builtins = new();

    public Task InitializeAsync() => _pg.StartAsync();
    public Task DisposeAsync() => _pg.DisposeAsync().AsTask();

    private sealed class FixedCaller(Guid userId) : IVaultCallerContext
    {
        public Guid UserId => userId;
        public Guid TenantId => Guid.Empty;
    }

    private async Task<(VaultDbContext db, ManifestResolver resolver)> BuildAsync(IVaultCallerContext caller)
    {
        var options = new DbContextOptionsBuilder<VaultDbContext>()
            .UseNpgsql(_pg.GetConnectionString(), n => n.MigrationsHistoryTable("__ef_migrations_history", "vault"))
            .Options;
        var db = new VaultDbContext(options, caller);
        await db.Database.MigrateAsync();
        return (db, new ManifestResolver(db, _builtins, caller));
    }

    private static OAuthManifest Custom(string key) => new()
    {
        Key = key,
        Name = key,
        AuthorizationEndpoint = $"https://{key}.example/authorize",
        TokenEndpoint = $"https://{key}.example/token",
        UserinfoEndpoint = $"https://{key}.example/userinfo",
        DefaultScopes = ["openid"],
    };

    [Fact]
    public async Task Upsert_OnBuiltinKey_IsRejected()
    {
        var builtinKey = _builtins.All[0].Key; // e.g. "github" / "google" / "microsoft"
        var (db, resolver) = await BuildAsync(new FixedCaller(Guid.NewGuid()));
        await using var _ = db;

        await Assert.ThrowsAsync<BuiltinManifestException>(() => resolver.UpsertOAuthAsync(Custom(builtinKey), default));

        // Nothing was written.
        Assert.Equal(0, await db.ProviderManifests.IgnoreQueryFilters().CountAsync());
    }

    [Fact]
    public async Task CustomManifest_IsScopedToOwner_AndDoesNotLeakAcrossUsers()
    {
        var alice = Guid.NewGuid();
        var bob = Guid.NewGuid();

        var (dbA, resolverA) = await BuildAsync(new FixedCaller(alice));
        await using (dbA)
        {
            await resolverA.UpsertOAuthAsync(Custom("acme"), default);

            // Owner sees it in both the keyed lookup and the list.
            Assert.NotNull(await resolverA.GetOAuthAsync("acme", alice, default));
            Assert.Contains(await resolverA.ListOAuthAsync(default), m => m.Key == "acme");
        }

        var (dbB, resolverB) = await BuildAsync(new FixedCaller(bob));
        await using (dbB)
        {
            // A different user cannot see or resolve Alice's custom provider.
            Assert.Null(await resolverB.GetOAuthAsync("acme", bob, default));
            Assert.DoesNotContain(await resolverB.ListOAuthAsync(default), m => m.Key == "acme");
        }
    }

    [Fact]
    public async Task GetOAuth_ResolvesByExplicitOwner_NotAmbientCaller()
    {
        // Models the anonymous OAuth callback: no ambient caller, identity comes from the state
        // row's owner. Resolution must key on the passed owner id, never leak another user's row.
        var alice = Guid.NewGuid();
        var bob = Guid.NewGuid();

        var (dbA, resolverA) = await BuildAsync(new FixedCaller(alice));
        await using (dbA)
        {
            await resolverA.UpsertOAuthAsync(Custom("acme"), default);
        }

        // Resolver built with an unrelated/empty ambient caller (as the callback would be).
        var (db, callbackResolver) = await BuildAsync(new FixedCaller(Guid.Empty));
        await using (db)
        {
            Assert.NotNull(await callbackResolver.GetOAuthAsync("acme", alice, default)); // owner via state row
            Assert.Null(await callbackResolver.GetOAuthAsync("acme", bob, default));      // wrong owner → no leak
        }
    }

    [Fact]
    public async Task Builtin_AlwaysWins_OverAStaleCustomRow()
    {
        var builtin = _builtins.All[0];
        var alice = Guid.NewGuid();

        var (db, resolver) = await BuildAsync(new FixedCaller(alice));
        await using var _ = db;

        // Inject a stale row that reuses a built-in key, bypassing the upsert guard.
        db.ProviderManifests.Add(new ProviderManifestEntity
        {
            Kind = ManifestResolver.OAuthKind,
            Key = builtin.Key,
            UserId = alice,
            DocumentJson = """{"key":"tampered","token_endpoint":"https://evil.example/token"}""",
        });
        await db.SaveChangesAsync();

        // Keyed lookup returns the immutable built-in, not the tampered row.
        var resolved = await resolver.GetOAuthAsync(builtin.Key, alice, default);
        Assert.NotNull(resolved);
        Assert.Equal(builtin.TokenEndpoint, resolved!.TokenEndpoint);

        // The list never lets a custom row shadow the built-in either.
        var listed = await resolver.ListOAuthAsync(default);
        Assert.Equal(builtin.TokenEndpoint, listed.Single(m => m.Key == builtin.Key).TokenEndpoint);
    }
}
