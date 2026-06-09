using System.Text.Json;
using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Persistence;
using DonkeyWork.Vault.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace DonkeyWork.Vault.Core.Manifests;

/// <summary>Thrown when a caller tries to create/override a manifest whose key is a built-in provider.</summary>
public sealed class BuiltinManifestException(string key)
    : Exception($"'{key}' is a built-in provider and cannot be overridden.")
{
    public string Key { get; } = key;
}

/// <summary>
/// Resolves OAuth provider manifests by overlaying a user's custom DB manifests on top of the
/// immutable embedded built-ins. Built-ins always win and can never be overridden; custom
/// manifests are owned per-user and only ever read back against an explicit owner id — the CRUD
/// paths use the authenticated <see cref="IVaultCallerContext"/>, while the anonymous OAuth
/// callback passes the owner captured on its state row. Scoped — uses the request DbContext.
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
            // Defence-in-depth: a stale custom row can never shadow an immutable built-in.
            if (oauthBuiltins.Get(row.Key) is not null)
            {
                continue;
            }
            map[row.Key] = JsonSerializer.Deserialize<OAuthManifest>(row.DocumentJson, Json)!;
        }
        return map.Values.OrderBy(m => m.Key, StringComparer.Ordinal).ToList();
    }

    /// <summary>
    /// Resolves a manifest for a specific owning user. Built-ins are authoritative and global;
    /// a custom manifest is matched only on <paramref name="userId"/>, so it can never resolve to
    /// another user's row. Query filters are ignored deliberately because the anonymous callback
    /// has no ambient caller — the explicit owner id is the scoping.
    /// </summary>
    public async Task<OAuthManifest?> GetOAuthAsync(string key, Guid userId, CancellationToken ct)
    {
        if (oauthBuiltins.Get(key) is { } builtin)
        {
            return builtin;
        }
        var row = await db.ProviderManifests.IgnoreQueryFilters()
            .FirstOrDefaultAsync(r => r.Kind == OAuthKind && r.Key == key && r.UserId == userId, ct);
        return row is not null ? JsonSerializer.Deserialize<OAuthManifest>(row.DocumentJson, Json) : null;
    }

    public bool IsOAuthBuiltin(string key) => oauthBuiltins.Get(key) is not null;

    public Task UpsertOAuthAsync(OAuthManifest m, CancellationToken ct)
    {
        if (IsOAuthBuiltin(m.Key))
        {
            throw new BuiltinManifestException(m.Key);
        }
        return UpsertAsync(OAuthKind, m.Key, JsonSerializer.Serialize(m, Json), ct);
    }

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
