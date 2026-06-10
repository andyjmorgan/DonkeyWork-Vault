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
    public async Task Template_IsLibraryOnly_NotResolvableUntilAdded()
    {
        var template = _builtins.All[0]; // e.g. "github" / "google" / "microsoft"
        var alice = Guid.NewGuid();
        var (db, resolver) = await BuildAsync(new FixedCaller(alice));
        await using var _ = db;

        // It's in the library...
        Assert.Contains(resolver.ListTemplates(), t => t.Key == template.Key);
        // ...but not connectable until added (no row → no resolution, no fallback to YAML).
        Assert.Null(await resolver.GetOAuthAsync(template.Key, alice, default));
        Assert.DoesNotContain(await resolver.ListOAuthAsync(default), m => m.Key == template.Key);
    }

    [Fact]
    public async Task Adding_CopiesTemplate_AsSelfContainedRow_WithParentBreadcrumb()
    {
        var template = _builtins.All[0];
        var alice = Guid.NewGuid();
        var (db, resolver) = await BuildAsync(new FixedCaller(alice));
        await using var _ = db;

        // Add = copy the whole template into a row; parent_id breadcrumbs back to the template.
        await resolver.UpsertOAuthAsync(new OAuthManifest
        {
            Key = template.Key, ParentId = template.Id, Name = template.Name,
            AuthorizationEndpoint = template.AuthorizationEndpoint, TokenEndpoint = template.TokenEndpoint,
            DefaultScopes = template.DefaultScopes,
        }, default);

        var resolved = await resolver.GetOAuthAsync(template.Key, alice, default);
        Assert.NotNull(resolved);
        Assert.NotEqual(Guid.Empty, resolved!.Id);
        Assert.NotEqual(template.Id, resolved.Id);          // its own identity, not the template's
        Assert.Equal(template.Id, resolved.ParentId);        // breadcrumb only
        Assert.Equal(template.TokenEndpoint, resolved.TokenEndpoint); // full self-contained copy
    }

    [Fact]
    public async Task DeletingProvider_CascadesConfigsAndTokens()
    {
        var alice = Guid.NewGuid();
        var (db, resolver) = await BuildAsync(new FixedCaller(alice));
        await using var _ = db;

        await resolver.UpsertOAuthAsync(Custom("acme"), default);
        var pid = (await db.ProviderManifests.IgnoreQueryFilters().FirstAsync(r => r.Key == "acme")).ProviderId;
        db.OAuthTokens.Add(new OAuthTokenEntity { UserId = alice, ProviderId = pid, ProviderKey = "acme", Account = "x", AccessTokenCipher = [1], RefreshTokenCipher = [] });
        await db.SaveChangesAsync();

        Assert.True(await resolver.DeleteAsync("oauth", "acme", default));
        Assert.Equal(0, await db.OAuthTokens.IgnoreQueryFilters().CountAsync(t => t.ProviderId == pid));
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
    public async Task AddedProvider_IsPerOwner_AndDoesNotLeak()
    {
        var template = _builtins.All[0];
        var alice = Guid.NewGuid();
        var bob = Guid.NewGuid();

        // Alice adds the template; Bob does not.
        var (dbA, resolverA) = await BuildAsync(new FixedCaller(alice));
        await using (dbA)
        {
            await resolverA.UpsertOAuthAsync(new OAuthManifest { Key = template.Key, ParentId = template.Id, TokenEndpoint = template.TokenEndpoint }, default);
            Assert.NotNull(await resolverA.GetOAuthAsync(template.Key, alice, default));
        }

        var (dbB, resolverB) = await BuildAsync(new FixedCaller(bob));
        await using (dbB)
        {
            // Bob hasn't added it → it's only a library template for him, not a resolvable provider.
            Assert.Null(await resolverB.GetOAuthAsync(template.Key, bob, default));
            Assert.DoesNotContain(await resolverB.ListOAuthAsync(default), m => m.Key == template.Key);
        }
    }
}
