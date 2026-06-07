namespace DonkeyWork.Vault.Persistence.Entities;

/// <summary>
/// A DB-stored provider manifest that overrides (or adds to) the embedded catalog.
/// Shared config, NOT user-scoped — deliberately not a <see cref="BaseEntity"/> so the
/// per-user query filter doesn't hide it. Document is the manifest serialized as JSON.
/// </summary>
public sealed class ProviderManifestEntity
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; } = Guid.Empty;
    public string Kind { get; set; } = string.Empty;   // "apikey" | "oauth"
    public string Key { get; set; } = string.Empty;
    public string DocumentJson { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? UpdatedAt { get; set; }
}
