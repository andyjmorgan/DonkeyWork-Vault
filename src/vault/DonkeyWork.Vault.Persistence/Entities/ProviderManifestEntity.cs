namespace DonkeyWork.Vault.Persistence.Entities;

/// <summary>
/// A DB-stored custom OAuth provider manifest, owned by the user that created it
/// (<see cref="BaseEntity.UserId"/>) and isolated by the per-user query filter. Built-in
/// providers ship as immutable embedded YAML; a custom manifest may NOT reuse a built-in key
/// (enforced at upsert) and is only ever resolved against its owner's id — including on the
/// anonymous OAuth callback, which scopes by the state row's owner. Document is the manifest
/// serialized as JSON.
/// </summary>
public sealed class ProviderManifestEntity : BaseEntity
{
    public string Kind { get; set; } = string.Empty;   // "apikey" | "oauth"
    public string Key { get; set; } = string.Empty;    // the slug / handle (per-user unique)

    /// <summary>Stable provider identity that configs/tokens link to (the provider's own id), so a
    /// slug rename never orphans. Distinct from <see cref="BaseEntity.Id"/> for historical continuity.</summary>
    public Guid ProviderId { get; set; }

    /// <summary>Historical breadcrumb: the library (YAML) template this provider was copied from, or
    /// <see cref="Guid.Empty"/> for a hand-authored custom provider. Never read for resolution.</summary>
    public Guid ParentId { get; set; }

    public string DocumentJson { get; set; } = string.Empty;
}
