namespace DonkeyWork.Vault.Persistence.Entities;

/// <summary>
/// One-time PKCE/state row for an in-flight OAuth authorization. NOT a
/// <see cref="BaseEntity"/>: the callback that consumes it is anonymous, so it must be
/// readable without a user context. The owning user is captured here at begin-time.
/// </summary>
public sealed class OAuthStateEntity
{
    public Guid Id { get; set; }
    public string State { get; set; } = string.Empty;
    public string Provider { get; set; } = string.Empty;
    public string CodeVerifier { get; set; } = string.Empty;
    public Guid OwnerUserId { get; set; }
    public Guid OwnerTenantId { get; set; }
    public string RedirectUri { get; set; } = string.Empty;
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
