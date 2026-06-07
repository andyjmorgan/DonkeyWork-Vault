namespace DonkeyWork.Vault.Persistence.Entities;

/// <summary>
/// A stored OAuth token set for a provider + account. Access/refresh tokens are
/// envelope-encrypted. Refreshed server-to-server using the provider config + manifest.
/// </summary>
public sealed class OAuthTokenEntity : BaseEntity
{
    public string ProviderKey { get; set; } = string.Empty;
    public string Account { get; set; } = string.Empty;   // external user id / email
    public byte[] AccessTokenCipher { get; set; } = [];
    public byte[] RefreshTokenCipher { get; set; } = [];
    public string? ScopesJson { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    public DateTimeOffset? LastRefreshedAt { get; set; }
}
