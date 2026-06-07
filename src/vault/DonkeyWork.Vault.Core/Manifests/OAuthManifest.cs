using System.Reflection;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace DonkeyWork.Vault.Core.Manifests;

public sealed class OAuthScopeDef
{
    public string Value { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public bool Sensitive { get; set; }
}

public sealed class OAuthManifest
{
    public string Key { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string IconUrl { get; set; } = string.Empty;
    public string DocsUrl { get; set; } = string.Empty;
    public string AuthorizationEndpoint { get; set; } = string.Empty;
    public string TokenEndpoint { get; set; } = string.Empty;
    public string UserinfoEndpoint { get; set; } = string.Empty;
    public string ScopeDelimiter { get; set; } = " ";
    public List<string> DefaultScopes { get; set; } = new();

    /// <summary>Curated, described scopes for a "pick your access" UI. Empty for discovered providers.</summary>
    public List<OAuthScopeDef> Scopes { get; set; } = new();
}

/// <summary>Loads + validates the embedded OAuth provider catalog at construction.</summary>
public sealed class OAuthManifestLoader
{
    private readonly IReadOnlyDictionary<string, OAuthManifest> _manifests;

    public OAuthManifestLoader()
    {
        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();

        var asm = typeof(OAuthManifestLoader).Assembly;
        var dict = new Dictionary<string, OAuthManifest>(StringComparer.OrdinalIgnoreCase);

        foreach (var resource in asm.GetManifestResourceNames()
                     .Where(n => n.Contains(".Embedded.oauth.") && n.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase)))
        {
            using var stream = asm.GetManifestResourceStream(resource)!;
            using var reader = new StreamReader(stream);
            var m = deserializer.Deserialize<OAuthManifest>(reader)
                ?? throw new InvalidOperationException($"OAuth manifest '{resource}' is empty.");
            if (string.IsNullOrWhiteSpace(m.Key) || string.IsNullOrWhiteSpace(m.TokenEndpoint))
            {
                throw new InvalidOperationException($"OAuth manifest '{resource}' missing key/token_endpoint.");
            }
            dict[m.Key] = m;
        }

        _manifests = dict;
    }

    public IReadOnlyList<OAuthManifest> All => _manifests.Values.OrderBy(m => m.Key, StringComparer.Ordinal).ToList();

    public OAuthManifest? Get(string key) => _manifests.TryGetValue(key, out var m) ? m : null;
}
