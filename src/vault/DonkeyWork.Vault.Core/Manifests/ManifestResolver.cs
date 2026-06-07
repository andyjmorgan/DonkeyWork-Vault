using System.Text.Json;
using DonkeyWork.Vault.Persistence;
using DonkeyWork.Vault.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace DonkeyWork.Vault.Core.Manifests;

/// <summary>
/// Resolves provider manifests by merging the embedded built-ins with DB overrides
/// (a DB row with the same key wins). Also performs manifest CRUD against the DB layer.
/// Scoped — uses the request DbContext.
/// </summary>
public sealed class ManifestResolver(
    VaultDbContext db,
    ApiKeyManifestLoader apiKeyBuiltins,
    OAuthManifestLoader oauthBuiltins)
{
    public const string ApiKeyKind = "apikey";
    public const string OAuthKind = "oauth";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async Task<IReadOnlyList<ApiKeyManifest>> ListApiKeyAsync(CancellationToken ct)
    {
        var map = apiKeyBuiltins.All.ToDictionary(m => m.Key, m => m, StringComparer.OrdinalIgnoreCase);
        foreach (var row in await db.ProviderManifests.Where(r => r.Kind == ApiKeyKind).ToListAsync(ct))
        {
            map[row.Key] = JsonSerializer.Deserialize<ApiKeyManifest>(row.DocumentJson, Json)!;
        }
        return map.Values.OrderBy(m => m.Key, StringComparer.Ordinal).ToList();
    }

    public async Task<ApiKeyManifest?> GetApiKeyAsync(string key, CancellationToken ct)
    {
        var row = await db.ProviderManifests.FirstOrDefaultAsync(r => r.Kind == ApiKeyKind && r.Key == key, ct);
        return row is not null ? JsonSerializer.Deserialize<ApiKeyManifest>(row.DocumentJson, Json) : apiKeyBuiltins.Get(key);
    }

    public async Task<IReadOnlyList<OAuthManifest>> ListOAuthAsync(CancellationToken ct)
    {
        var map = oauthBuiltins.All.ToDictionary(m => m.Key, m => m, StringComparer.OrdinalIgnoreCase);
        foreach (var row in await db.ProviderManifests.Where(r => r.Kind == OAuthKind).ToListAsync(ct))
        {
            map[row.Key] = JsonSerializer.Deserialize<OAuthManifest>(row.DocumentJson, Json)!;
        }
        return map.Values.OrderBy(m => m.Key, StringComparer.Ordinal).ToList();
    }

    public async Task<OAuthManifest?> GetOAuthAsync(string key, CancellationToken ct)
    {
        var row = await db.ProviderManifests.FirstOrDefaultAsync(r => r.Kind == OAuthKind && r.Key == key, ct);
        return row is not null ? JsonSerializer.Deserialize<OAuthManifest>(row.DocumentJson, Json) : oauthBuiltins.Get(key);
    }

    public bool IsOAuthBuiltin(string key) => oauthBuiltins.Get(key) is not null;
    public bool IsApiKeyBuiltin(string key) => apiKeyBuiltins.Get(key) is not null;

    public Task UpsertApiKeyAsync(ApiKeyManifest m, CancellationToken ct) =>
        UpsertAsync(ApiKeyKind, m.Key, JsonSerializer.Serialize(m, Json), ct);

    public Task UpsertOAuthAsync(OAuthManifest m, CancellationToken ct) =>
        UpsertAsync(OAuthKind, m.Key, JsonSerializer.Serialize(m, Json), ct);

    private async Task UpsertAsync(string kind, string key, string json, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            throw new ArgumentException("manifest key is required.");
        }
        var row = await db.ProviderManifests.FirstOrDefaultAsync(r => r.Kind == kind && r.Key == key, ct);
        if (row is null)
        {
            db.ProviderManifests.Add(new ProviderManifestEntity { Kind = kind, Key = key, DocumentJson = json });
        }
        else
        {
            row.DocumentJson = json;
            row.UpdatedAt = DateTimeOffset.UtcNow;
        }
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Removes a DB override/custom manifest. Built-ins re-surface after removing their override.</summary>
    public async Task<bool> DeleteAsync(string kind, string key, CancellationToken ct)
    {
        var row = await db.ProviderManifests.FirstOrDefaultAsync(r => r.Kind == kind && r.Key == key, ct);
        if (row is null)
        {
            return false;
        }
        db.ProviderManifests.Remove(row);
        await db.SaveChangesAsync(ct);
        return true;
    }
}
