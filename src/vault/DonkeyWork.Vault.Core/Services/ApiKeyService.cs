using System.Text.Json;
using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Core.Crypto;
using DonkeyWork.Vault.Core.Manifests;
using DonkeyWork.Vault.Persistence;
using DonkeyWork.Vault.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace DonkeyWork.Vault.Core.Services;

public sealed record StoredApiKey(Guid Id, string Provider, string Name, DateTimeOffset CreatedAt, DateTimeOffset? LastUsedAt);

public sealed record ApiKeySecret(string Secret, IReadOnlyDictionary<string, string> Fields);

/// <summary>Thrown when a referenced provider manifest does not exist.</summary>
public sealed class ManifestNotFoundException(string provider) : Exception($"Unknown provider '{provider}'.")
{
    public string Provider { get; } = provider;
}

/// <summary>Thrown when create input fails manifest validation.</summary>
public sealed class CredentialValidationException(string message) : Exception(message);

public interface IApiKeyService
{
    Task<StoredApiKey> CreateAsync(string provider, string name, IReadOnlyDictionary<string, string> fields, CancellationToken ct);
    Task<IReadOnlyList<StoredApiKey>> ListAsync(CancellationToken ct);
    Task<ApiKeySecret?> GetAsync(string provider, string? name, CancellationToken ct);
    Task<bool> DeleteAsync(Guid id, CancellationToken ct);
    ApiKeyManifest? DescribeShape(string provider);
}

public sealed class ApiKeyService(
    VaultDbContext db,
    IEnvelopeCipher cipher,
    ApiKeyManifestLoader manifests,
    IVaultCallerContext caller) : IApiKeyService
{
    public async Task<StoredApiKey> CreateAsync(string provider, string name, IReadOnlyDictionary<string, string> fields, CancellationToken ct)
    {
        var manifest = manifests.Get(provider) ?? throw new ManifestNotFoundException(provider);

        if (string.IsNullOrWhiteSpace(name))
        {
            throw new CredentialValidationException("name is required.");
        }

        foreach (var f in manifest.Fields.Where(f => f.Required))
        {
            if (!fields.TryGetValue(f.Name, out var v) || string.IsNullOrEmpty(v))
            {
                throw new CredentialValidationException($"missing required field '{f.Name}'.");
            }
        }

        var known = manifest.Fields.Select(f => f.Name).ToHashSet(StringComparer.Ordinal);
        var filtered = fields.Where(kv => known.Contains(kv.Key))
            .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);

        var plaintext = JsonSerializer.SerializeToUtf8Bytes(filtered);

        var entity = new ApiKeyEntity
        {
            UserId = caller.UserId,
            TenantId = caller.TenantId,
            ProviderKey = provider,
            Name = name,
            FieldsCipher = cipher.Encrypt(plaintext),
        };

        db.ApiKeys.Add(entity);
        await db.SaveChangesAsync(ct);

        return new StoredApiKey(entity.Id, entity.ProviderKey, entity.Name, entity.CreatedAt, entity.LastUsedAt);
    }

    public async Task<IReadOnlyList<StoredApiKey>> ListAsync(CancellationToken ct) =>
        await db.ApiKeys
            .OrderByDescending(k => k.CreatedAt)
            .Select(k => new StoredApiKey(k.Id, k.ProviderKey, k.Name, k.CreatedAt, k.LastUsedAt))
            .ToListAsync(ct);

    public async Task<ApiKeySecret?> GetAsync(string provider, string? name, CancellationToken ct)
    {
        var query = db.ApiKeys.Where(k => k.ProviderKey == provider);
        if (!string.IsNullOrEmpty(name))
        {
            query = query.Where(k => k.Name == name);
        }

        var entity = await query.OrderByDescending(k => k.CreatedAt).FirstOrDefaultAsync(ct);
        if (entity is null)
        {
            return null;
        }

        var plaintext = cipher.Decrypt(entity.FieldsCipher);
        var dict = JsonSerializer.Deserialize<Dictionary<string, string>>(plaintext) ?? new();

        var primary = manifests.Get(provider)?.PrimarySecretField ?? "api_key";
        var secret = dict.TryGetValue(primary, out var v) ? v : dict.Values.FirstOrDefault() ?? string.Empty;

        entity.LastUsedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);

        return new ApiKeySecret(secret, dict);
    }

    public async Task<bool> DeleteAsync(Guid id, CancellationToken ct)
    {
        var entity = await db.ApiKeys.FirstOrDefaultAsync(k => k.Id == id, ct);
        if (entity is null)
        {
            return false;
        }

        db.ApiKeys.Remove(entity);
        await db.SaveChangesAsync(ct);
        return true;
    }

    public ApiKeyManifest? DescribeShape(string provider) => manifests.Get(provider);
}
