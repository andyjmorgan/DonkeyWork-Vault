namespace DonkeyWork.Vault.Persistence.Entities;

/// <summary>
/// A non-OAuth API key credential. ProviderKey is a manifest id (e.g. "grafana",
/// "openai") — no enum. FieldsCipher is the envelope-encrypted JSON map of the
/// manifest's declared fields (e.g. { "api_key": "..." }).
/// </summary>
public sealed class ApiKeyEntity : BaseEntity
{
    public string ProviderKey { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public byte[] FieldsCipher { get; set; } = [];

    // Self-describing metadata (non-secret) so an agent can discover what the credential is,
    // where it's used, how to send it, and where to read the docs.
    public string? Description { get; set; }
    public string? BaseUrl { get; set; }
    public string? DocsUrl { get; set; }
    public string? HeaderName { get; set; }
    public string? Prefix { get; set; }

    public DateTimeOffset? LastUsedAt { get; set; }
}
