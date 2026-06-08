using System.Security.Cryptography;
using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Persistence;
using DonkeyWork.Vault.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace DonkeyWork.Vault.Core.Services;

/// <summary>Metadata for a scoped access key. The secret is never carried here (show-once).</summary>
public sealed record StoredAccessKey(
    Guid Id, string Name, string? Description, IReadOnlyList<string> Scopes,
    bool Enabled, string Prefix, DateTimeOffset CreatedAt, DateTimeOffset? LastUsedAt);

/// <summary>The result of authenticating a presented secret.</summary>
public sealed record AccessKeyPrincipal(Guid UserId, Guid TenantId, IReadOnlyList<string> Scopes, string Name);

public interface IAccessKeyService
{
    /// <summary>Mints a key; returns its metadata plus the plaintext secret (shown ONCE).</summary>
    Task<(StoredAccessKey Key, string Secret)> CreateAsync(string name, string? description, IReadOnlyList<string> scopes, CancellationToken ct);
    Task<IReadOnlyList<StoredAccessKey>> ListAsync(CancellationToken ct);
    Task<StoredAccessKey?> SetEnabledAsync(Guid id, bool enabled, CancellationToken ct);
    Task<bool> DeleteAsync(Guid id, CancellationToken ct);

    /// <summary>Resolves a presented secret to its owner + scopes, or null if unknown/disabled.</summary>
    Task<AccessKeyPrincipal?> AuthenticateAsync(string secret, CancellationToken ct);
}

public sealed class AccessKeyService(VaultDbContext db, IVaultCallerContext caller) : IAccessKeyService
{
    public const string SecretPrefix = "dwv_";

    /// <summary>The scopes a key may carry.</summary>
    public static readonly IReadOnlySet<string> ValidScopes = new HashSet<string>
    {
        "frontend:read", "frontend:readwrite", "vault:read", "vault:readwrite",
    };

    public async Task<(StoredAccessKey Key, string Secret)> CreateAsync(
        string name, string? description, IReadOnlyList<string> scopes, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new CredentialValidationException("name is required.");
        }
        var normalized = (scopes ?? []).Where(s => !string.IsNullOrWhiteSpace(s)).Distinct().ToArray();
        if (normalized.Length == 0)
        {
            throw new CredentialValidationException("at least one scope is required.");
        }
        var invalid = normalized.Where(s => !ValidScopes.Contains(s)).ToArray();
        if (invalid.Length > 0)
        {
            throw new CredentialValidationException($"unknown scope(s): {string.Join(", ", invalid)}.");
        }

        // dwv_<43 base64url chars> (32 random bytes). Hash for storage; keep a short display prefix.
        var raw = RandomNumberGenerator.GetBytes(32);
        var secret = SecretPrefix + Base64Url(raw);
        var prefix = secret[..Math.Min(secret.Length, 9)];

        var entity = new AccessKeyEntity
        {
            UserId = caller.UserId,
            TenantId = caller.TenantId,
            Name = name,
            Description = description,
            KeyHash = Hash(secret),
            KeyPrefix = prefix,
            Scopes = normalized,
            Enabled = true,
        };
        db.AccessKeys.Add(entity);
        await db.SaveChangesAsync(ct);
        return (ToStored(entity), secret);
    }

    public async Task<IReadOnlyList<StoredAccessKey>> ListAsync(CancellationToken ct) =>
        (await db.AccessKeys.OrderByDescending(k => k.CreatedAt).ToListAsync(ct)).Select(ToStored).ToList();

    public async Task<StoredAccessKey?> SetEnabledAsync(Guid id, bool enabled, CancellationToken ct)
    {
        var entity = await db.AccessKeys.FirstOrDefaultAsync(k => k.Id == id, ct);
        if (entity is null)
        {
            return null;
        }
        entity.Enabled = enabled;
        entity.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);
        return ToStored(entity);
    }

    public async Task<bool> DeleteAsync(Guid id, CancellationToken ct)
    {
        var entity = await db.AccessKeys.FirstOrDefaultAsync(k => k.Id == id, ct);
        if (entity is null)
        {
            return false;
        }
        db.AccessKeys.Remove(entity);
        await db.SaveChangesAsync(ct);
        return true;
    }

    public async Task<AccessKeyPrincipal?> AuthenticateAsync(string secret, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(secret))
        {
            return null;
        }
        var hash = Hash(secret);
        // Auth precedes knowing the caller, so bypass the per-user query filter; the hash is unique.
        var entity = await db.AccessKeys.IgnoreQueryFilters()
            .FirstOrDefaultAsync(k => k.KeyHash == hash, ct);
        if (entity is null || !entity.Enabled)
        {
            return null;
        }
        entity.LastUsedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);
        return new AccessKeyPrincipal(entity.UserId, entity.TenantId, entity.Scopes, entity.Name);
    }

    private static byte[] Hash(string secret) => SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(secret));

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static StoredAccessKey ToStored(AccessKeyEntity k) =>
        new(k.Id, k.Name, k.Description, k.Scopes, k.Enabled, k.KeyPrefix, k.CreatedAt, k.LastUsedAt);
}
