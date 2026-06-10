using System.Text.Json;
using System.Text.RegularExpressions;
using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Persistence;
using DonkeyWork.Vault.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace DonkeyWork.Vault.Core.Manifests;

/// <summary>
/// Resolves OAuth provider manifests. Identity is a stable <c>provider_id</c> GUID — the static id
/// baked into a built-in's YAML template, or a custom provider's own id — and configs/tokens link to
/// that, never to a mutable slug. A user may <b>customize a built-in</b> by storing a per-user overlay
/// row (keyed by the built-in's slug): unedited fields keep inheriting live from the YAML template,
/// while edited scopes / default-scopes / authorize-params override it (scopes hard-replace). A
/// brand-new slug is a full custom provider. Everything is owned per-user and only ever resolved
/// against an explicit owner id — the CRUD paths use the authenticated <see cref="IVaultCallerContext"/>,
/// the anonymous OAuth callback passes the owner captured on its state row. Scoped to the request DbContext.
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

    public async Task<IReadOnlyList<OAuthManifest>> ListOAuthAsync(CancellationToken ct)
    {
        var map = oauthBuiltins.All.ToDictionary(m => m.Key, m => m, StringComparer.OrdinalIgnoreCase);
        var rows = await db.ProviderManifests
            .Where(r => r.Kind == OAuthKind && r.UserId == caller.UserId)
            .ToListAsync(ct);
        foreach (var row in rows)
        {
            map[row.Key] = Materialize(row);
        }
        return map.Values.OrderBy(m => m.Key, StringComparer.Ordinal).ToList();
    }

    /// <summary>The caller's own OAuth manifest slugs (DB-backed overlays / custom providers).</summary>
    public async Task<IReadOnlySet<string>> ListCustomOAuthKeysAsync(CancellationToken ct)
    {
        var keys = await db.ProviderManifests
            .Where(r => r.Kind == OAuthKind && r.UserId == caller.UserId)
            .Select(r => r.Key)
            .ToListAsync(ct);
        return keys.ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Resolves a manifest by slug for a specific owning user (built-in template, possibly with the
    /// user's overlay applied, else the user's custom provider). Query filters are ignored deliberately
    /// because the anonymous callback has no ambient caller — the explicit owner id is the scoping.
    /// </summary>
    public async Task<OAuthManifest?> GetOAuthAsync(string key, Guid userId, CancellationToken ct)
    {
        var row = await db.ProviderManifests.IgnoreQueryFilters()
            .FirstOrDefaultAsync(r => r.Kind == OAuthKind && r.Key == key && r.UserId == userId, ct);
        if (row is not null)
        {
            return Materialize(row);
        }
        return oauthBuiltins.Get(key);
    }

    /// <summary>The stable provider id for a slug, owned by <paramref name="userId"/>, or null if unknown.</summary>
    public async Task<Guid?> ResolveProviderIdAsync(string key, Guid userId, CancellationToken ct)
    {
        if (oauthBuiltins.Get(key) is { } builtin)
        {
            return builtin.Id;
        }
        var row = await db.ProviderManifests.IgnoreQueryFilters()
            .FirstOrDefaultAsync(r => r.Kind == OAuthKind && r.Key == key && r.UserId == userId, ct);
        return row?.ProviderId;
    }

    public bool IsOAuthBuiltin(string key) => oauthBuiltins.Get(key) is not null;

    /// <summary>
    /// Upserts the caller's OAuth provider. A built-in slug stores a sparse overlay (only the
    /// editable scopes / default-scopes / authorize-params), keyed by the built-in's catalog GUID; a
    /// brand-new slug is a full custom provider with its own stable id.
    /// </summary>
    public async Task UpsertOAuthAsync(OAuthManifest m, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(m.Key) || !SlugRegex().IsMatch(m.Key))
        {
            throw new ArgumentException($"provider slug '{m.Key}' must be non-empty and match [a-zA-Z0-9_-].");
        }

        Guid providerId;
        string json;
        if (oauthBuiltins.Get(m.Key) is { } builtin)
        {
            // Overlay of a built-in: store only the editable bits; the rest inherits live from YAML.
            providerId = builtin.Id;
            json = JsonSerializer.Serialize(
                new OAuthManifest { Scopes = m.Scopes, DefaultScopes = m.DefaultScopes, AuthorizeParams = m.AuthorizeParams },
                Json);
        }
        else
        {
            var existing = await db.ProviderManifests
                .FirstOrDefaultAsync(r => r.Kind == OAuthKind && r.Key == m.Key && r.UserId == caller.UserId, ct);
            providerId = existing is { ProviderId: var pid } && pid != Guid.Empty ? pid : Guid.NewGuid();
            m.Id = providerId;
            json = JsonSerializer.Serialize(m, Json);
        }

        await UpsertRowAsync(OAuthKind, m.Key, providerId, json, ct);
    }

    private async Task UpsertRowAsync(string kind, string key, Guid providerId, string json, CancellationToken ct)
    {
        var row = await db.ProviderManifests
            .FirstOrDefaultAsync(r => r.Kind == kind && r.Key == key && r.UserId == caller.UserId, ct);
        if (row is null)
        {
            db.ProviderManifests.Add(new ProviderManifestEntity
            {
                Kind = kind,
                Key = key,
                ProviderId = providerId,
                DocumentJson = json,
                UserId = caller.UserId,
                TenantId = caller.TenantId,
            });
        }
        else
        {
            row.ProviderId = providerId;
            row.DocumentJson = json;
            row.UpdatedAt = DateTimeOffset.UtcNow;
        }
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Removes one of the caller's own provider rows. For a <b>custom</b> provider this also cascades
    /// its configs + tokens (the identity disappears). For a built-in <b>overlay</b> (reset to template)
    /// the catalog identity persists, so configs/tokens are deliberately left intact.
    /// </summary>
    public async Task<bool> DeleteAsync(string kind, string key, CancellationToken ct)
    {
        var row = await db.ProviderManifests
            .FirstOrDefaultAsync(r => r.Kind == kind && r.Key == key && r.UserId == caller.UserId, ct);
        if (row is null)
        {
            return false;
        }

        if (kind == OAuthKind && oauthBuiltins.Get(key) is null)
        {
            var pid = row.ProviderId;
            db.OAuthProviderConfigs.RemoveRange(db.OAuthProviderConfigs.Where(c => c.ProviderId == pid));
            db.OAuthTokens.RemoveRange(db.OAuthTokens.Where(t => t.ProviderId == pid));
        }

        db.ProviderManifests.Remove(row);
        await db.SaveChangesAsync(ct);
        return true;
    }

    /// <summary>Turns a stored row into a resolved manifest: an overlay merged onto its built-in base,
    /// or a custom provider's full document (id + slug stamped from the row).</summary>
    private OAuthManifest Materialize(ProviderManifestEntity row)
    {
        var stored = JsonSerializer.Deserialize<OAuthManifest>(row.DocumentJson, Json)!;
        if (oauthBuiltins.Get(row.Key) is { } builtin)
        {
            return MergeOverlay(builtin, stored);
        }
        stored.Id = row.ProviderId;
        stored.Key = row.Key;
        return stored;
    }

    /// <summary>Built-in template base with the user's overlay applied: scalars/endpoints always inherit
    /// from the template; scopes / default-scopes / authorize-params override when the overlay sets them.</summary>
    private static OAuthManifest MergeOverlay(OAuthManifest baseManifest, OAuthManifest overlay)
    {
        var merged = JsonSerializer.Deserialize<OAuthManifest>(JsonSerializer.Serialize(baseManifest, Json), Json)!;
        if (overlay.Scopes.Count > 0)
        {
            merged.Scopes = overlay.Scopes;
        }
        if (overlay.DefaultScopes.Count > 0)
        {
            merged.DefaultScopes = overlay.DefaultScopes;
        }
        if (overlay.AuthorizeParams.Count > 0)
        {
            merged.AuthorizeParams = overlay.AuthorizeParams;
        }
        merged.Id = baseManifest.Id;
        return merged;
    }
}
