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
    public DateTimeOffset? LastUsedAt { get; set; }
}
