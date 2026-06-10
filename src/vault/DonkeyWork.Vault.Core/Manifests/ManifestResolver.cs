using System.Text.Json;
using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Persistence;
using DonkeyWork.Vault.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace DonkeyWork.Vault.Core.Manifests;

/// <summary>
/// Resolves OAuth provider manifests by overlaying a user's custom DB manifests on top of the
/// embedded built-in templates. A user may fork a built-in into a per-user override to add
/// scopes; resolution order is therefore <b>custom DB record → built-in template</b>. Custom
/// manifests are owned per-user and only ever read back against an explicit owner id — the CRUD
/// paths use the authenticated <see cref="IVaultCallerContext"/>, while the anonymous OAuth
/// callback passes the owner captured on its state row, so an override only ever affects its own
/// owner and can never resolve to (or redirect) another user's flow. Scoped — uses the request
/// DbContext.
/// </summary>
public sealed class ManifestResolver(
    VaultDbContext db,
    OAuthManifestLoader oauthBuiltins,
    IVaultCallerContext caller)
{
    public const string OAuthKind = "oauth";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async Task<IReadOnlyList<OAuthManifest>> ListOAuthAsync(CancellationToken ct)
    {
        var map = oauthBuiltins.All.ToDictionary(m => m.Key, m => m, StringComparer.OrdinalIgnoreCase);
        var rows = await db.ProviderManifests
            .Where(r => r.Kind == OAuthKind && r.UserId == caller.UserId)
            .ToListAsync(ct);
        foreach (var row in rows)
        {
            // A caller's custom record overrides the built-in template of the same key (per-user only).
            map[row.Key] = JsonSerializer.Deserialize<OAuthManifest>(row.DocumentJson, Json)!;
        }
        return map.Values.OrderBy(m => m.Key, StringComparer.Ordinal).ToList();
    }

    /// <summary>The caller's own OAuth manifest keys (DB-backed overrides / custom providers).</summary>
    public async Task<IReadOnlySet<string>> ListCustomOAuthKeysAsync(CancellationToken ct)
    {
        var keys = await db.ProviderManifests
            .Where(r => r.Kind == OAuthKind && r.UserId == caller.UserId)
            .Select(r => r.Key)
            .ToListAsync(ct);
        return keys.ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Resolves a manifest for a specific owning user. The user's own custom record wins; absent
    /// one, the built-in template is the fallback. A custom manifest is matched only on
    /// <paramref name="userId"/>, so it can never resolve to another user's row. Query filters are
    /// ignored deliberately because the anonymous callback has no ambient caller — the explicit
    /// owner id is the scoping.
    /// </summary>
    public async Task<OAuthManifest?> GetOAuthAsync(string key, Guid userId, CancellationToken ct)
    {
        var row = await db.ProviderManifests.IgnoreQueryFilters()
            .FirstOrDefaultAsync(r => r.Kind == OAuthKind && r.Key == key && r.UserId == userId, ct);
        if (row is not null)
        {
            return JsonSerializer.Deserialize<OAuthManifest>(row.DocumentJson, Json);
        }
        return oauthBuiltins.Get(key);
    }

    public bool IsOAuthBuiltin(string key) => oauthBuiltins.Get(key) is not null;

    /// <summary>
    /// Upserts the caller's custom manifest. A built-in key is allowed and creates a per-user
    /// override (which then wins for that user only); a brand-new key is a custom provider.
    /// </summary>
    public Task UpsertOAuthAsync(OAuthManifest m, CancellationToken ct) =>
        UpsertAsync(OAuthKind, m.Key, JsonSerializer.Serialize(m, Json), ct);

    private async Task UpsertAsync(string kind, string key, string json, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            throw new ArgumentException("manifest key is required.");
        }
        var row = await db.ProviderManifests
            .FirstOrDefaultAsync(r => r.Kind == kind && r.Key == key && r.UserId == caller.UserId, ct);
        if (row is null)
        {
            db.ProviderManifests.Add(new ProviderManifestEntity
            {
                Kind = kind,
                Key = key,
                DocumentJson = json,
                UserId = caller.UserId,
                TenantId = caller.TenantId,
            });
        }
        else
        {
            row.DocumentJson = json;
            row.UpdatedAt = DateTimeOffset.UtcNow;
        }
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Removes one of the caller's own custom manifests. Built-in keys own no rows, so return false.</summary>
    public async Task<bool> DeleteAsync(string kind, string key, CancellationToken ct)
    {
        var row = await db.ProviderManifests
            .FirstOrDefaultAsync(r => r.Kind == kind && r.Key == key && r.UserId == caller.UserId, ct);
        if (row is null)
        {
            return false;
        }
        db.ProviderManifests.Remove(row);
        await db.SaveChangesAsync(ct);
        return true;
    }
}
