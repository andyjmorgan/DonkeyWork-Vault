namespace DonkeyWork.Vault.Core.Manifests;

/// <summary>
/// Declarative description of a non-OAuth API-key provider. Loaded from embedded YAML
/// (and, later, DB overrides). No enum — the provider is identified by <see cref="Key"/>.
/// </summary>
public sealed class ApiKeyManifest
{
    public string Key { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string IconUrl { get; set; } = string.Empty;
    public string DocsUrl { get; set; } = string.Empty;
    public ApiKeyAuth Auth { get; set; } = new();
    public string BaseUrl { get; set; } = string.Empty;
    public List<ApiKeyFieldDef> Fields { get; set; } = new();

    /// <summary>The field whose value is the "secret" returned by GetApiKey.</summary>
    public string PrimarySecretField =>
        Fields.FirstOrDefault(f => f.Secret)?.Name
        ?? Fields.FirstOrDefault()?.Name
        ?? "api_key";
}

public sealed class ApiKeyAuth
{
    public string Scheme { get; set; } = "header";   // header | basic
    public string Header { get; set; } = string.Empty;
    public string Prefix { get; set; } = string.Empty;
    public Dictionary<string, string> StaticHeaders { get; set; } = new();
}

public sealed class ApiKeyFieldDef
{
    public string Name { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    public bool Secret { get; set; }
    public bool Required { get; set; }
}
