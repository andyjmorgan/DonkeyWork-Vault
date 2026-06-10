using System.Text.Json;
using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Contracts.Audit;
using DonkeyWork.Vault.Core.Audit;
using DonkeyWork.Vault.Core.Crypto;
using DonkeyWork.Vault.Core.Manifests;
using DonkeyWork.Vault.Core.OAuth;
using DonkeyWork.Vault.Persistence;
using DonkeyWork.Vault.Persistence.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace DonkeyWork.Vault.Core.Services;

public sealed record BeginAuthResult(string AuthorizeUrl, string State);
public sealed record CompleteAuthResult(string Provider, string Account, IReadOnlyList<string> Scopes, DateTimeOffset? ExpiresAt);

public sealed class OAuthAuthorizationException(string message) : Exception(message);

public interface IOAuthFlowService
{
    Task<BeginAuthResult> BeginAsync(string provider, IReadOnlyList<string>? scopes, string publicBaseUrl, CancellationToken ct);
    Task<CompleteAuthResult> CompleteAsync(string code, string state, CancellationToken ct);
}

public sealed class OAuthFlowService(
    VaultDbContext db,
    IEnvelopeCipher cipher,
    ManifestResolver manifests,
    IVaultCallerContext caller,
    IHttpClientFactory httpFactory,
    AuditEmitter audit,
    ILogger<OAuthFlowService> logger) : IOAuthFlowService
{
    public async Task<BeginAuthResult> BeginAsync(string provider, IReadOnlyList<string>? scopes, string publicBaseUrl, CancellationToken ct)
    {
        var manifest = await manifests.GetOAuthAsync(provider, caller.UserId, ct)
            ?? throw new OAuthAuthorizationException($"unknown OAuth provider '{provider}'.");
        var config = await db.OAuthProviderConfigs.FirstOrDefaultAsync(c => c.ProviderId == manifest.Id, ct)
            ?? throw new OAuthAuthorizationException($"no OAuth app config for '{provider}'. Add client_id/secret first.");

        var clientId = cipher.DecryptToString(config.ClientIdCipher);
        var scopeList = scopes is { Count: > 0 }
            ? scopes
            : (config.ScopesJson is not null ? JsonSerializer.Deserialize<List<string>>(config.ScopesJson)! : manifest.DefaultScopes);

        // Allowlist: only scopes the provider actually declares (catalog ∪ defaults) may reach the
        // authorize URL, so a stray stored scope (e.g. a bogus "offline") can never be forwarded.
        var (kept, dropped) = FilterScopesToCatalog(manifest, scopeList);
        if (dropped.Count > 0)
        {
            logger.LogWarning("Dropped {Count} scope(s) not in the {Provider} catalog: {Dropped}",
                dropped.Count, provider, string.Join(", ", dropped));
        }
        scopeList = kept;

        var verifier = PkceUtility.GenerateVerifier();
        var state = PkceUtility.RandomState();
        // Static, provider-agnostic callback — the state row carries the provider, so the registered
        // redirect URI is one constant URL per app and survives a slug rename.
        var redirectUri = $"{publicBaseUrl.TrimEnd('/')}/api/oauth/callback";

        db.OAuthStates.Add(new OAuthStateEntity
        {
            State = state,
            Provider = provider,
            CodeVerifier = verifier,
            OwnerUserId = caller.UserId,
            OwnerTenantId = caller.TenantId,
            RedirectUri = redirectUri,
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10),
        });
        await db.SaveChangesAsync(ct);

        var q = new Dictionary<string, string>
        {
            ["client_id"] = clientId,
            ["redirect_uri"] = redirectUri,
            ["response_type"] = "code",
            ["scope"] = string.Join(manifest.ScopeDelimiter, scopeList),
            ["state"] = state,
            ["code_challenge"] = PkceUtility.Challenge(verifier),
            ["code_challenge_method"] = "S256",
        };
        // Provider-specific authorize params come from the manifest (YAML template or custom override),
        // e.g. Google's access_type=offline / prompt=consent or Dropbox's token_access_type=offline.
        foreach (var (k, v) in manifest.AuthorizeParams)
        {
            q[k] = v;
        }

        var url = manifest.AuthorizationEndpoint + "?" +
            string.Join("&", q.Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
        return new BeginAuthResult(url, state);
    }

    /// <summary>
    /// Restricts requested scopes to what the provider declares (catalog values ∪ default scopes),
    /// returning the kept set (original order preserved) and the dropped set. When the provider
    /// declares neither, nothing can be validated against, so the request passes through unfiltered.
    /// </summary>
    public static (IReadOnlyList<string> Kept, IReadOnlyList<string> Dropped) FilterScopesToCatalog(
        OAuthManifest manifest, IReadOnlyList<string> requested)
    {
        var allowed = manifest.Scopes.Select(s => s.Value)
            .Concat(manifest.DefaultScopes)
            .ToHashSet(StringComparer.Ordinal);
        if (allowed.Count == 0)
        {
            return (requested, []);
        }
        var kept = requested.Where(allowed.Contains).ToList();
        var dropped = requested.Where(s => !allowed.Contains(s)).ToList();
        return (kept, dropped);
    }

    public async Task<CompleteAuthResult> CompleteAsync(string code, string state, CancellationToken ct)
    {
        try
        {
            return await CompleteCoreAsync(code, state, ct);
        }
        catch (Exception ex)
        {
            // A failed anonymous callback is security-relevant; record it. The provider is unknown
            // here (the state may be invalid). ex.Message is status-only (no provider body).
            audit.Emit(AuditEventType.TokenAdded, AuditOutcome.Failure,
                targetKind: "oauth_token", detail: ex.Message);
            throw;
        }
    }

    private async Task<CompleteAuthResult> CompleteCoreAsync(string code, string state, CancellationToken ct)
    {
        // State is a standalone (non-user-scoped) row; readable in the anonymous callback. Identity
        // (provider + owner) comes entirely from the state row — the URL no longer carries it.
        var stateRow = await db.OAuthStates.FirstOrDefaultAsync(s => s.State == state, ct)
            ?? throw new OAuthAuthorizationException("invalid or expired state.");
        var provider = stateRow.Provider;
        if (stateRow.ExpiresAt < DateTimeOffset.UtcNow)
        {
            throw new OAuthAuthorizationException("invalid or expired state.");
        }

        // Atomic claim: exactly one callback may consume a state row. A concurrent duplicate (or a
        // replay) deletes zero rows and is rejected before any token exchange.
        if (await db.OAuthStates.Where(s => s.Id == stateRow.Id).ExecuteDeleteAsync(ct) == 0)
        {
            throw new OAuthAuthorizationException("state already used.");
        }

        var manifest = await manifests.GetOAuthAsync(provider, stateRow.OwnerUserId, ct)
            ?? throw new OAuthAuthorizationException($"unknown OAuth provider '{provider}'.");
        var config = await db.OAuthProviderConfigs.IgnoreQueryFilters()
            .FirstOrDefaultAsync(c => c.UserId == stateRow.OwnerUserId && c.ProviderId == manifest.Id, ct)
            ?? throw new OAuthAuthorizationException($"no OAuth app config for '{provider}'.");

        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["client_id"] = cipher.DecryptToString(config.ClientIdCipher),
            ["client_secret"] = cipher.DecryptToString(config.ClientSecretCipher),
            ["redirect_uri"] = stateRow.RedirectUri,
            ["code_verifier"] = stateRow.CodeVerifier,
        };

        var client = httpFactory.CreateClient("oauth");
        using var req = new HttpRequestMessage(HttpMethod.Post, manifest.TokenEndpoint) { Content = new FormUrlEncodedContent(form) };
        req.Headers.TryAddWithoutValidation("Accept", "application/json");
        req.Headers.TryAddWithoutValidation("User-Agent", "donkeywork-vault");
        using var resp = await client.SendAsync(req, ct);
        var body = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
        {
            throw new OAuthAuthorizationException($"token exchange failed: HTTP {(int)resp.StatusCode}");
        }

        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;
        var accessToken = root.GetProperty("access_token").GetString()!;
        string? refreshToken = root.TryGetProperty("refresh_token", out var rt) ? rt.GetString() : null;
        DateTimeOffset? expiresAt = root.TryGetProperty("expires_in", out var ei) && ei.TryGetInt64(out var s)
            ? DateTimeOffset.UtcNow.AddSeconds(s) : null;
        var scopes = (root.TryGetProperty("scope", out var sc) ? sc.GetString() : null)?
            .Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries).ToList()
            ?? (config.ScopesJson is not null ? JsonSerializer.Deserialize<List<string>>(config.ScopesJson)! : new());

        var account = await FetchAccountAsync(client, manifest, accessToken, ct);

        var existing = await db.OAuthTokens.IgnoreQueryFilters()
            .FirstOrDefaultAsync(t => t.UserId == stateRow.OwnerUserId && t.ProviderId == manifest.Id && t.Account == account, ct);
        if (existing is null)
        {
            db.OAuthTokens.Add(new OAuthTokenEntity
            {
                UserId = stateRow.OwnerUserId,
                TenantId = stateRow.OwnerTenantId,
                ProviderId = manifest.Id,
                ProviderKey = provider,
                Account = account,
                AccessTokenCipher = cipher.EncryptString(accessToken),
                RefreshTokenCipher = refreshToken is not null ? cipher.EncryptString(refreshToken) : [],
                ScopesJson = JsonSerializer.Serialize(scopes),
                ExpiresAt = expiresAt,
                LastRefreshedAt = DateTimeOffset.UtcNow,
            });
        }
        else
        {
            existing.AccessTokenCipher = cipher.EncryptString(accessToken);
            if (refreshToken is not null)
            {
                existing.RefreshTokenCipher = cipher.EncryptString(refreshToken);
            }
            existing.ScopesJson = JsonSerializer.Serialize(scopes);
            existing.ExpiresAt = expiresAt;
            existing.LastRefreshedAt = DateTimeOffset.UtcNow;
        }

        // The state row was already claimed (deleted) atomically above.
        await db.SaveChangesAsync(ct);

        // Anonymous callback: identity comes from the state row, and there is no access key, so the
        // access_key_* fields are null. IP/headers are still captured from the ambient context.
        audit.Emit(AuditEventType.TokenAdded, AuditOutcome.Success,
            targetKind: "oauth_token", targetProvider: provider, targetAccount: account,
            userId: stateRow.OwnerUserId, tenantId: stateRow.OwnerTenantId);

        return new CompleteAuthResult(provider, account, scopes, expiresAt);
    }

    private static async Task<string> FetchAccountAsync(HttpClient client, OAuthManifest manifest, string accessToken, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(manifest.UserinfoEndpoint))
        {
            return "default";
        }
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, manifest.UserinfoEndpoint);
            req.Headers.TryAddWithoutValidation("Authorization", $"Bearer {accessToken}");
            req.Headers.TryAddWithoutValidation("Accept", "application/json");
            req.Headers.TryAddWithoutValidation("User-Agent", "donkeywork-vault");
            using var resp = await client.SendAsync(req, ct);
            if (!resp.IsSuccessStatusCode)
            {
                return "default";
            }
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
            var r = doc.RootElement;
            foreach (var key in new[] { "email", "mail", "userPrincipalName", "preferred_username", "login", "sub" })
            {
                if (r.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { Length: > 0 } val)
                {
                    return val;
                }
            }
            return "default";
        }
        catch
        {
            return "default";
        }
    }
}
