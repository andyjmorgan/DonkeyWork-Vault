using System.Text.Json;
using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Contracts.Audit;
using DonkeyWork.Vault.Core.Audit;
using DonkeyWork.Vault.Core.Crypto;
using DonkeyWork.Vault.Core.Manifests;
using DonkeyWork.Vault.Persistence;
using DonkeyWork.Vault.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace DonkeyWork.Vault.Core.Services;

public sealed record OAuthAccessToken(string AccessToken, DateTimeOffset? ExpiresAt, IReadOnlyList<string> Scopes);

public sealed record OAuthTokenSummary(
    Guid Id, string Provider, string Account, DateTimeOffset? ExpiresAt, DateTimeOffset? LastRefreshedAt, IReadOnlyList<string> Scopes);

public sealed class OAuthRefreshException(string message) : Exception(message);

public interface IOAuthTokenService
{
    Task<OAuthAccessToken?> GetAccessTokenAsync(string provider, string? account, CancellationToken ct);
    Task<IReadOnlyList<OAuthTokenSummary>> ListAsync(CancellationToken ct);
}

public sealed class OAuthTokenService(
    VaultDbContext db,
    IEnvelopeCipher cipher,
    ManifestResolver manifests,
    IVaultCallerContext caller,
    IHttpClientFactory httpFactory,
    AuditEmitter audit) : IOAuthTokenService
{
    private static readonly TimeSpan RefreshWindow = TimeSpan.FromSeconds(60);

    public async Task<IReadOnlyList<OAuthTokenSummary>> ListAsync(CancellationToken ct) =>
        await db.OAuthTokens
            .OrderBy(t => t.ProviderKey)
            .Select(t => new OAuthTokenSummary(
                t.Id, t.ProviderKey, t.Account, t.ExpiresAt, t.LastRefreshedAt,
                t.ScopesJson == null ? new List<string>() : JsonSerializer.Deserialize<List<string>>(t.ScopesJson)!))
            .ToListAsync(ct);

    public async Task<OAuthAccessToken?> GetAccessTokenAsync(string provider, string? account, CancellationToken ct)
    {
        var query = db.OAuthTokens.Where(t => t.ProviderKey == provider);
        if (!string.IsNullOrEmpty(account))
        {
            query = query.Where(t => t.Account == account);
        }

        var token = await query.OrderByDescending(t => t.CreatedAt).FirstOrDefaultAsync(ct);
        if (token is null)
        {
            // Not found is still an access event (Failure).
            audit.Emit(AuditEventType.TokenAccessed, AuditOutcome.Failure,
                targetKind: "oauth_token", targetProvider: provider, targetAccount: account,
                detail: "no token for provider/account");
            return null;
        }

        // Emit the access on every read, whether or not a refresh follows (a refresh adds its own
        // TokenRefreshed event — two events, by design).
        audit.Emit(AuditEventType.TokenAccessed, AuditOutcome.Success,
            targetKind: "oauth_token", targetProvider: token.ProviderKey, targetAccount: token.Account);

        var scopes = token.ScopesJson is null ? new List<string>() : JsonSerializer.Deserialize<List<string>>(token.ScopesJson)!;

        var fresh = token.ExpiresAt is null || token.ExpiresAt > DateTimeOffset.UtcNow.Add(RefreshWindow);
        if (fresh)
        {
            return new OAuthAccessToken(cipher.DecryptToString(token.AccessTokenCipher), token.ExpiresAt, scopes);
        }

        // Needs refresh — load the provider app config + manifest.
        var manifest = await manifests.GetOAuthAsync(provider, ct);
        var config = await db.OAuthProviderConfigs.FirstOrDefaultAsync(c => c.ProviderKey == provider, ct);
        if (manifest is null || config is null || token.RefreshTokenCipher.Length == 0)
        {
            // Can't refresh; return what we have.
            return new OAuthAccessToken(cipher.DecryptToString(token.AccessTokenCipher), token.ExpiresAt, scopes);
        }

        var refreshed = await RefreshAsync(manifest, config, token, ct);
        await db.SaveChangesAsync(ct);
        return refreshed;
    }

    private async Task<OAuthAccessToken> RefreshAsync(OAuthManifest manifest, OAuthProviderConfigEntity config, OAuthTokenEntity token, CancellationToken ct)
    {
        try
        {
            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = cipher.DecryptToString(token.RefreshTokenCipher),
                ["client_id"] = cipher.DecryptToString(config.ClientIdCipher),
                ["client_secret"] = cipher.DecryptToString(config.ClientSecretCipher),
            };

            using var req = new HttpRequestMessage(HttpMethod.Post, manifest.TokenEndpoint)
            {
                Content = new FormUrlEncodedContent(form),
            };
            req.Headers.TryAddWithoutValidation("Accept", "application/json");
            req.Headers.TryAddWithoutValidation("User-Agent", "donkeywork-vault");

            var client = httpFactory.CreateClient("oauth");
            using var resp = await client.SendAsync(req, ct);
            var body = await resp.Content.ReadAsStringAsync(ct);
            if (!resp.IsSuccessStatusCode)
            {
                // Status only — the raw provider body can carry token-like material and this
                // message flows into the audit Detail; never persist the body.
                throw new OAuthRefreshException($"refresh failed for {manifest.Key}: HTTP {(int)resp.StatusCode}");
            }

            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            if (!root.TryGetProperty("access_token", out var at))
            {
                throw new OAuthRefreshException($"refresh response for {manifest.Key} had no access_token");
            }
            var accessToken = at.GetString()!;

            DateTimeOffset? expiresAt = null;
            if (root.TryGetProperty("expires_in", out var ei) && ei.TryGetInt64(out var secs))
            {
                expiresAt = DateTimeOffset.UtcNow.AddSeconds(secs);
            }

            token.AccessTokenCipher = cipher.EncryptString(accessToken);
            if (root.TryGetProperty("refresh_token", out var rt) && rt.GetString() is { Length: > 0 } newRefresh)
            {
                token.RefreshTokenCipher = cipher.EncryptString(newRefresh);
            }
            token.ExpiresAt = expiresAt;
            token.LastRefreshedAt = DateTimeOffset.UtcNow;

            // One TokenRefreshed event per successful refresh.
            audit.Emit(AuditEventType.TokenRefreshed, AuditOutcome.Success,
                targetKind: "oauth_token", targetProvider: token.ProviderKey, targetAccount: token.Account);

            var scopes = token.ScopesJson is null ? new List<string>() : JsonSerializer.Deserialize<List<string>>(token.ScopesJson)!;
            return new OAuthAccessToken(accessToken, expiresAt, scopes);
        }
        catch (OAuthRefreshException ex)
        {
            // Capture the failed refresh with its reason, then rethrow unchanged.
            audit.Emit(AuditEventType.TokenRefreshed, AuditOutcome.Failure,
                targetKind: "oauth_token", targetProvider: token.ProviderKey, targetAccount: token.Account,
                detail: ex.Message);
            throw;
        }
    }
}
