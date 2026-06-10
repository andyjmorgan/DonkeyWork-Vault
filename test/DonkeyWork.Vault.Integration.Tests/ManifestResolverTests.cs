using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Core.Manifests;
using DonkeyWork.Vault.Persistence;
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
    public async Task Customizing_Builtin_StoresOverlay_InheritsEndpoints_OverridesScopes()
    {
        var builtin = _builtins.All[0]; // e.g. "github" / "google" / "microsoft"
        var alice = Guid.NewGuid();
        var (db, resolver) = await BuildAsync(new FixedCaller(alice));
        await using var _ = db;

        // Customize: only default scopes are edited; endpoints are NOT supplied (overlay semantics).
        await resolver.UpsertOAuthAsync(new OAuthManifest { Key = builtin.Key, DefaultScopes = ["custom.scope"] }, default);

        var resolved = await resolver.GetOAuthAsync(builtin.Key, alice, default);
        Assert.NotNull(resolved);
        Assert.Equal(builtin.Id, resolved!.Id);                       // identity = the catalog GUID
        Assert.Equal(builtin.TokenEndpoint, resolved.TokenEndpoint);  // unedited fields inherit from the template
        Assert.Equal(["custom.scope"], resolved.DefaultScopes);       // edited field overrides
        Assert.Contains(builtin.Key, await resolver.ListCustomOAuthKeysAsync(default));
        Assert.Equal(1, await db.ProviderManifests.IgnoreQueryFilters().CountAsync());
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
    public async Task BuiltinTemplate_IsFallback_AndOverrideIsPerOwner()
    {
        var builtin = _builtins.All[0];
        var alice = Guid.NewGuid();
        var bob = Guid.NewGuid();

        // Alice forks the built-in; Bob leaves it untouched.
        var (dbA, resolverA) = await BuildAsync(new FixedCaller(alice));
        await using (dbA)
        {
            await resolverA.UpsertOAuthAsync(Custom(builtin.Key), default);
        }

        var (dbB, resolverB) = await BuildAsync(new FixedCaller(bob));
        await using (dbB)
        {
            // Bob has no override → resolves the built-in template (the fallback), in lookup and list.
            var resolved = await resolverB.GetOAuthAsync(builtin.Key, bob, default);
            Assert.NotNull(resolved);
            Assert.Equal(builtin.TokenEndpoint, resolved!.TokenEndpoint);
            Assert.Equal(builtin.TokenEndpoint, (await resolverB.ListOAuthAsync(default)).Single(m => m.Key == builtin.Key).TokenEndpoint);
            Assert.DoesNotContain(builtin.Key, await resolverB.ListCustomOAuthKeysAsync(default));
        }
    }
}
