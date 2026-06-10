namespace DonkeyWork.Vault.Persistence.Entities;

/// <summary>
/// Per-user OAuth app credentials for a provider (manifest id). client_id/secret are
/// envelope-encrypted. Endpoints come from the provider manifest, not this row.
/// </summary>
public sealed class OAuthProviderConfigEntity : BaseEntity
{
    /// <summary>Stable provider identity this config belongs to (built-in catalog GUID or custom
    /// provider id). Survives a slug rename; the link everything resolves through.</summary>
    public Guid ProviderId { get; set; }

    public string ProviderKey { get; set; } = string.Empty;
    public byte[] ClientIdCipher { get; set; } = [];
    public byte[] ClientSecretCipher { get; set; } = [];
    public string? ScopesJson { get; set; }
    public string? RedirectUri { get; set; }
}
