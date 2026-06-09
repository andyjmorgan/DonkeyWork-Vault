using System.Text.Json;
using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Contracts.Audit;
using DonkeyWork.Vault.Core.Audit;
using DonkeyWork.Vault.Core.Crypto;
using DonkeyWork.Vault.Persistence;
using DonkeyWork.Vault.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace DonkeyWork.Vault.Core.Services;

public sealed record OAuthConfigSummary(
    Guid Id, string Provider, string ClientIdMasked, IReadOnlyList<string> Scopes, string? RedirectUri, DateTimeOffset CreatedAt);

public interface IOAuthProviderConfigService
{
    Task<IReadOnlyList<OAuthConfigSummary>> ListAsync(CancellationToken ct);
    Task<Guid> UpsertAsync(string provider, string clientId, string? clientSecret, IReadOnlyList<string> scopes, string? redirectUri, CancellationToken ct);
    Task<bool> DeleteAsync(Guid id, CancellationToken ct);
}

public sealed class OAuthProviderConfigService(
    VaultDbContext db, IEnvelopeCipher cipher, IVaultCallerContext caller, AuditEmitter audit) : IOAuthProviderConfigService
{
    public async Task<IReadOnlyList<OAuthConfigSummary>> ListAsync(CancellationToken ct)
    {
        var rows = await db.OAuthProviderConfigs.OrderBy(c => c.ProviderKey).ToListAsync(ct);
        return rows.Select(c => new OAuthConfigSummary(
            c.Id, c.ProviderKey, Mask(cipher.DecryptToString(c.ClientIdCipher)),
            c.ScopesJson is null ? new List<string>() : JsonSerializer.Deserialize<List<string>>(c.ScopesJson)!,
            c.RedirectUri, c.CreatedAt)).ToList();
    }

    public async Task<Guid> UpsertAsync(string provider, string clientId, string? clientSecret, IReadOnlyList<string> scopes, string? redirectUri, CancellationToken ct)
    {
        var row = await db.OAuthProviderConfigs.FirstOrDefaultAsync(c => c.ProviderKey == provider, ct);
        var scopesJson = JsonSerializer.Serialize(scopes);
        var isNew = row is null;
        if (row is null)
        {
            if (string.IsNullOrEmpty(clientSecret))
            {
                throw new CredentialValidationException("client secret is required when creating a provider config.");
            }
            row = new OAuthProviderConfigEntity
            {
                UserId = caller.UserId,
                TenantId = caller.TenantId,
                ProviderKey = provider,
                ClientIdCipher = cipher.EncryptString(clientId),
                ClientSecretCipher = cipher.EncryptString(clientSecret),
                ScopesJson = scopesJson,
                RedirectUri = redirectUri,
            };
            db.OAuthProviderConfigs.Add(row);
        }
        else
        {
            row.ClientIdCipher = cipher.EncryptString(clientId);
            if (!string.IsNullOrEmpty(clientSecret))
            {
                row.ClientSecretCipher = cipher.EncryptString(clientSecret);
            }
            row.ScopesJson = scopesJson;
            row.RedirectUri = redirectUri;
            row.UpdatedAt = DateTimeOffset.UtcNow;
        }
        await db.SaveChangesAsync(ct);

        // Only the first creation of a provider config is a CredentialCreated event.
        if (isNew)
        {
            audit.Emit(AuditEventType.CredentialCreated, AuditOutcome.Success,
                targetKind: "provider_config", targetProvider: provider, targetName: provider);
        }

        return row.Id;
    }

    public async Task<bool> DeleteAsync(Guid id, CancellationToken ct)
    {
        var row = await db.OAuthProviderConfigs.FirstOrDefaultAsync(c => c.Id == id, ct);
        if (row is null)
        {
            return false;
        }
        db.OAuthProviderConfigs.Remove(row);
        await db.SaveChangesAsync(ct);
        return true;
    }

    private static string Mask(string s) =>
        s.Length <= 10 ? "***" : $"{s[..6]}…{s[^4..]}";
}
