namespace DonkeyWork.Vault.Persistence.Entities;

/// <summary>
/// A scoped authentication credential ("API key") that lets the CLI/agents authenticate to the
/// vault and the portal. Show-once: only a SHA-256 hash of the secret is stored (KeyHash, the
/// global lookup index) plus a non-secret display prefix (e.g. "dwv_AbC12"). The full secret is
/// never recoverable. Scopes gate what the key may do; Enabled toggles it on/off.
/// </summary>
public sealed class AccessKeyEntity : BaseEntity
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }

    /// <summary>SHA-256 of the secret. Globally unique; looked up before the caller is known.</summary>
    public byte[] KeyHash { get; set; } = [];

    /// <summary>Non-secret leading fragment of the key, for display (e.g. "dwv_AbC12").</summary>
    public string KeyPrefix { get; set; } = string.Empty;

    /// <summary>Granted scopes, e.g. "vault:read", "frontend:readwrite".</summary>
    public string[] Scopes { get; set; } = [];

    public bool Enabled { get; set; } = true;
    public DateTimeOffset? LastUsedAt { get; set; }
}
