using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Contracts.Audit;
using DonkeyWork.Vault.Core.Audit;
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
    string? Header, string? Prefix, string? Username, DateTimeOffset CreatedAt, DateTimeOffset? LastUsedAt);

public sealed record ApiKeySecret(
    string Secret, string? Header, string? Prefix, string? Username, string? BaseUrl, string? DocsUrl, string? Description);

/// <summary>Thrown when create input is invalid.</summary>
public sealed class CredentialValidationException(string message) : Exception(message);

public interface IApiKeyService
{
    Task<StoredApiKey> CreateAsync(string name, string secret, string? description, string? baseUrl, string? docsUrl, string? header, string? prefix, string? username, CancellationToken ct);
    Task<IReadOnlyList<StoredApiKey>> ListAsync(CancellationToken ct);
    Task<ApiKeySecret?> GetByNameAsync(string name, CancellationToken ct);
    Task<bool> DeleteAsync(Guid id, CancellationToken ct);
}

public sealed class ApiKeyService(
    VaultDbContext db, IEnvelopeCipher cipher, IVaultCallerContext caller, AuditEmitter audit) : IApiKeyService
{
    public async Task<StoredApiKey> CreateAsync(string name, string secret, string? description, string? baseUrl, string? docsUrl, string? header, string? prefix, string? username, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new CredentialValidationException("name is required.");
        }

        // username present ⇒ HTTP Basic. The username is the delimiter's left side, so it
        // must not contain a colon. Empty/whitespace means "not Basic".
        username = string.IsNullOrWhiteSpace(username) ? null : username;
        if (username is not null && username.Contains(':'))
        {
            throw new CredentialValidationException("username must not contain ':' (it delimits Basic credentials).");
        }

        var existing = await db.ApiKeys.FirstOrDefaultAsync(k => k.Name == name, ct);
        var isNew = existing is null;
        if (existing is null)
        {
            if (string.IsNullOrEmpty(secret))
            {
                throw new CredentialValidationException("secret is required.");
            }
            existing = new ApiKeyEntity { UserId = caller.UserId, TenantId = caller.TenantId, ProviderKey = string.Empty, Name = name };
            db.ApiKeys.Add(existing);
        }

        // Basic requires both halves; on edit a blank secret keeps the stored password, so
        // only enforce "password present" when creating or when there's nothing stored yet.
        if (username is not null && string.IsNullOrEmpty(secret) && (isNew || existing.FieldsCipher.Length == 0))
        {
            throw new CredentialValidationException("Basic auth requires a password (secret) alongside the username.");
        }

        existing.Description = description;
        existing.BaseUrl = baseUrl;
        existing.DocsUrl = docsUrl;
        existing.Username = username;
        // For Basic, default the header to Authorization so list/shape read sensibly; the
        // prefix is irrelevant (the value is assembled as "Basic base64(user:pass)").
        existing.HeaderName = username is not null
            ? (string.IsNullOrWhiteSpace(header) ? "Authorization" : header)
            : (string.IsNullOrWhiteSpace(header) ? null : header);
        existing.Prefix = username is not null ? null : prefix;
        if (!string.IsNullOrEmpty(secret)) // blank on edit keeps the existing secret
        {
            existing.FieldsCipher = cipher.EncryptString(secret);
        }

        await db.SaveChangesAsync(ct);

        // Only a create is a CredentialCreated event; an edit reuses the existing row.
        if (isNew)
        {
            audit.Emit(AuditEventType.CredentialCreated, AuditOutcome.Success,
                targetKind: "api_key", targetName: existing.Name);
        }

        return ToStored(existing);
    }

    public async Task<IReadOnlyList<StoredApiKey>> ListAsync(CancellationToken ct) =>
        (await db.ApiKeys.OrderByDescending(k => k.CreatedAt).ToListAsync(ct)).Select(ToStored).ToList();

    public async Task<ApiKeySecret?> GetByNameAsync(string name, CancellationToken ct)
    {
        var entity = await db.ApiKeys.FirstOrDefaultAsync(k => k.Name == name, ct);
        if (entity is null)
        {
            // A reveal attempt for a missing credential is still an access event (Failure).
            audit.Emit(AuditEventType.TokenAccessed, AuditOutcome.Failure,
                targetKind: "api_key", targetName: name, detail: "credential not found");
            return null;
        }
        var secret = cipher.DecryptToString(entity.FieldsCipher);
        entity.LastUsedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);

        audit.Emit(AuditEventType.TokenAccessed, AuditOutcome.Success,
            targetKind: "api_key", targetName: entity.Name);

        return new ApiKeySecret(secret, entity.HeaderName, entity.Prefix, entity.Username, entity.BaseUrl, entity.DocsUrl, entity.Description);
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
        new(k.Id, k.Name, k.Description, k.BaseUrl, k.DocsUrl, k.HeaderName, k.Prefix, k.Username, k.CreatedAt, k.LastUsedAt);
}
