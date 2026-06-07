using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Core.Crypto;
using DonkeyWork.Vault.Persistence;
using DonkeyWork.Vault.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace DonkeyWork.Vault.Core.Services;

/// <summary>
/// A stored, self-describing API key. Metadata (description/base url/docs/header/prefix) lets
/// an agent discover what the credential is, where it's used and how to send it — without any
/// fixed provider "type".
/// </summary>
public sealed record StoredApiKey(
    Guid Id, string Name, string? Description, string? BaseUrl, string? DocsUrl,
    string? Header, string? Prefix, DateTimeOffset CreatedAt, DateTimeOffset? LastUsedAt);

public sealed record ApiKeySecret(
    string Secret, string? Header, string? Prefix, string? BaseUrl, string? DocsUrl, string? Description);

/// <summary>Thrown when create input is invalid.</summary>
public sealed class CredentialValidationException(string message) : Exception(message);

public interface IApiKeyService
{
    Task<StoredApiKey> CreateAsync(string name, string secret, string? description, string? baseUrl, string? docsUrl, string? header, string? prefix, CancellationToken ct);
    Task<IReadOnlyList<StoredApiKey>> ListAsync(CancellationToken ct);
    Task<ApiKeySecret?> GetByNameAsync(string name, CancellationToken ct);
    Task<bool> DeleteAsync(Guid id, CancellationToken ct);
}

public sealed class ApiKeyService(
    VaultDbContext db, IEnvelopeCipher cipher, IVaultCallerContext caller) : IApiKeyService
{
    public async Task<StoredApiKey> CreateAsync(string name, string secret, string? description, string? baseUrl, string? docsUrl, string? header, string? prefix, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new CredentialValidationException("name is required.");
        }
        if (string.IsNullOrEmpty(secret))
        {
            throw new CredentialValidationException("secret is required.");
        }

        var existing = await db.ApiKeys.FirstOrDefaultAsync(k => k.Name == name, ct);
        if (existing is null)
        {
            existing = new ApiKeyEntity { UserId = caller.UserId, TenantId = caller.TenantId, ProviderKey = string.Empty, Name = name };
            db.ApiKeys.Add(existing);
        }
        existing.Description = description;
        existing.BaseUrl = baseUrl;
        existing.DocsUrl = docsUrl;
        existing.HeaderName = string.IsNullOrWhiteSpace(header) ? "Authorization" : header;
        existing.Prefix = prefix;
        existing.FieldsCipher = cipher.EncryptString(secret);

        await db.SaveChangesAsync(ct);
        return ToStored(existing);
    }

    public async Task<IReadOnlyList<StoredApiKey>> ListAsync(CancellationToken ct) =>
        (await db.ApiKeys.OrderByDescending(k => k.CreatedAt).ToListAsync(ct)).Select(ToStored).ToList();

    public async Task<ApiKeySecret?> GetByNameAsync(string name, CancellationToken ct)
    {
        var entity = await db.ApiKeys.FirstOrDefaultAsync(k => k.Name == name, ct);
        if (entity is null)
        {
            return null;
        }
        var secret = cipher.DecryptToString(entity.FieldsCipher);
        entity.LastUsedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);
        return new ApiKeySecret(secret, entity.HeaderName, entity.Prefix, entity.BaseUrl, entity.DocsUrl, entity.Description);
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

    private static StoredApiKey ToStored(ApiKeyEntity k) =>
        new(k.Id, k.Name, k.Description, k.BaseUrl, k.DocsUrl, k.HeaderName, k.Prefix, k.CreatedAt, k.LastUsedAt);
}
