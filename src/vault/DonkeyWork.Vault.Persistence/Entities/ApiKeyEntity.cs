namespace DonkeyWork.Vault.Persistence.Entities;

/// <summary>
/// A non-OAuth API key credential. ProviderKey is a manifest id (e.g. "grafana",
/// "openai") — no enum. FieldsCipher is the envelope-encrypted secret: the API key,
/// or the password when <see cref="Username"/> is set (HTTP Basic auth).
/// </summary>
public sealed class ApiKeyEntity : BaseEntity
{
    public string ProviderKey { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public byte[] FieldsCipher { get; set; } = [];

    // Explicit credential kind (discriminator) so an agent knows how to use the secret.
    // Stored verbatim as the snake_case wire string (e.g. "opaque", "ssh"); the typed
    // CredentialKind enum lives at the Core/API boundary. Defaults to opaque.
    public string Kind { get; set; } = "opaque";

    // Self-describing metadata (non-secret) so an agent can discover what the credential is,
    // where it's used, how to send it, and where to read the docs.
    public string? Description { get; set; }
    public string? BaseUrl { get; set; }
    public string? DocsUrl { get; set; }
    public string? HeaderName { get; set; }
    public string? Prefix { get; set; }

    // HTTP Basic auth. When set, the credential is sent as
    // Authorization: Basic base64(Username ":" secret) instead of HeaderName + Prefix.
    // Non-secret (the password lives in FieldsCipher) so it's safe to surface in list/shape.
    public string? Username { get; set; }

    public DateTimeOffset? LastUsedAt { get; set; }
}
