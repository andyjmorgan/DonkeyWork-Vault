using System.Text.Json;
using System.Text.RegularExpressions;
using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Persistence;
using DonkeyWork.Vault.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace DonkeyWork.Vault.Core.Manifests;

/// <summary>
/// Resolves OAuth providers. The embedded YAML is a <b>library</b> of templates — it is never seeded
/// and never resolved against directly. When a user <b>adds</b> a provider (from a template or
/// hand-authored), the whole manifest is copied into a self-contained per-user DB row with its own
/// stable <c>provider_id</c> (the identity configs/tokens link to) and a <c>parent_id</c> breadcrumb
/// pointing at the source template (kept for history only — never read to resolve or rebuild). So a
/// provider is connectable only once it has a row; templates just populate the add-picker. Per-user
/// and only ever resolved against an explicit owner id. Scoped to the request DbContext.
/// </summary>
public sealed partial class ManifestResolver(
    VaultDbContext db,
    OAuthManifestLoader oauthBuiltins,
    IVaultCallerContext caller)
{
    public const string OAuthKind = "oauth";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    [GeneratedRegex("^[a-zA-Z0-9_-]+$")]
    private static partial Regex SlugRegex();

    /// <summary>The library of templates available to add (embedded YAML). Read-only catalog.</summary>
    public IReadOnlyList<OAuthManifest> ListTemplates() => oauthBuiltins.All;

    /// <summary>The caller's added providers (DB rows). Templates are not included until added.</summary>
    public async Task<IReadOnlyList<OAuthManifest>> ListOAuthAsync(CancellationToken ct)
    {
        var rows = await db.ProviderManifests
            .Where(r => r.Kind == OAuthKind && r.UserId == caller.UserId)
            .ToListAsync(ct);
        return rows.Select(Materialize).OrderBy(m => m.Key, StringComparer.Ordinal).ToList();
    }

    /// <summary>
    /// Resolves an added provider by slug for a specific owning user (DB row only — the YAML library is
    /// never a resolution fallback). Query filters are ignored deliberately because the anonymous
    /// callback has no ambient caller; the explicit owner id is the scoping.
    /// </summary>
    public async Task<OAuthManifest?> GetOAuthAsync(string key, Guid userId, CancellationToken ct)
    {
        var row = await db.ProviderManifests.IgnoreQueryFilters()
            .FirstOrDefaultAsync(r => r.Kind == OAuthKind && r.Key == key && r.UserId == userId, ct);
        return row is null ? null : Materialize(row);
    }

    /// <summary>The stable provider id for an added slug, owned by <paramref name="userId"/>, or null.</summary>
    public async Task<Guid?> ResolveProviderIdAsync(string key, Guid userId, CancellationToken ct)
    {
        var row = await db.ProviderManifests.IgnoreQueryFilters()
            .FirstOrDefaultAsync(r => r.Kind == OAuthKind && r.Key == key && r.UserId == userId, ct);
        return row?.ProviderId;
    }

    /// <summary>
    /// Adds or edits one of the caller's providers. The full manifest is stored as a self-contained
    /// row; the row keeps its stable provider id across edits, and its parent_id breadcrumb is set on
    /// first add (preserved thereafter).
    /// </summary>
    public async Task UpsertOAuthAsync(OAuthManifest m, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(m.Key) || !SlugRegex().IsMatch(m.Key))
        {
            throw new ArgumentException($"provider slug '{m.Key}' must be non-empty and match [a-zA-Z0-9_-].");
        }

        var row = await db.ProviderManifests
            .FirstOrDefaultAsync(r => r.Kind == OAuthKind && r.Key == m.Key && r.UserId == caller.UserId, ct);
        var providerId = row is { ProviderId: var pid } && pid != Guid.Empty ? pid : Guid.NewGuid();
        var parentId = row is { ParentId: var par } && par != Guid.Empty ? par : m.ParentId;

        m.Id = providerId;
        m.ParentId = parentId;
        var json = JsonSerializer.Serialize(m, Json);

        if (row is null)
        {
            db.ProviderManifests.Add(new ProviderManifestEntity
            {
                Kind = OAuthKind,
                Key = m.Key,
                ProviderId = providerId,
                ParentId = parentId,
                DocumentJson = json,
                UserId = caller.UserId,
                TenantId = caller.TenantId,
            });
        }
        else
        {
            row.ProviderId = providerId;
            row.ParentId = parentId;
            row.DocumentJson = json;
            row.UpdatedAt = DateTimeOffset.UtcNow;
        }
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Removes one of the caller's providers and cascades its configs + tokens (the identity
    /// is gone). Built-in templates own no rows, so an un-added slug returns false.</summary>
    public async Task<bool> DeleteAsync(string kind, string key, CancellationToken ct)
    {
        var row = await db.ProviderManifests
            .FirstOrDefaultAsync(r => r.Kind == kind && r.Key == key && r.UserId == caller.UserId, ct);
        if (row is null)
        {
            return false;
        }

        if (kind == OAuthKind)
        {
            var pid = row.ProviderId;
            db.OAuthProviderConfigs.RemoveRange(db.OAuthProviderConfigs.Where(c => c.ProviderId == pid));
            db.OAuthTokens.RemoveRange(db.OAuthTokens.Where(t => t.ProviderId == pid));
        }

        db.ProviderManifests.Remove(row);
        await db.SaveChangesAsync(ct);
        return true;
    }

    /// <summary>A stored row's full manifest, with id / parent / slug stamped from the row.</summary>
    private static OAuthManifest Materialize(ProviderManifestEntity row)
    {
        var m = JsonSerializer.Deserialize<OAuthManifest>(row.DocumentJson, Json)!;
        m.Id = row.ProviderId;
        m.ParentId = row.ParentId;
        m.Key = row.Key;
        return m;
    }
}
