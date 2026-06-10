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
    /// <summary>Stable provider identity that configs/tokens link to — the DB row's own id once added,
    /// or the static catalog GUID for a library template before it's copied into a row.</summary>
    public Guid Id { get; set; }

    /// <summary>Historical breadcrumb only: the library template this provider was copied from
    /// (<see cref="Guid.Empty"/> for a hand-authored custom provider). Never used to resolve or rebuild.</summary>
    public Guid ParentId { get; set; }

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

    /// <summary>
    /// Extra query parameters appended to the authorization URL, e.g. Google's
    /// <c>access_type=offline</c>/<c>prompt=consent</c> or Dropbox's <c>token_access_type=offline</c>
    /// (required to be issued a refresh token). Declared in YAML templates and editable per provider.
    /// </summary>
    public Dictionary<string, string> AuthorizeParams { get; set; } = new();
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
        var byId = new Dictionary<Guid, OAuthManifest>();

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
            // The static id is this provider's stable identity that configs/tokens link to; a missing
            // or duplicated id silently corrupts those links, so fail fast at startup.
            if (m.Id == Guid.Empty)
            {
                throw new InvalidOperationException($"OAuth manifest '{resource}' missing a stable 'id' GUID.");
            }
            if (!byId.TryAdd(m.Id, m))
            {
                throw new InvalidOperationException($"OAuth manifest '{resource}' reuses id {m.Id}, already used by '{byId[m.Id].Key}'.");
            }
            dict[m.Key] = m;
        }

        _manifests = dict;
        _byId = byId;
    }

    private readonly IReadOnlyDictionary<Guid, OAuthManifest> _byId;

    public IReadOnlyList<OAuthManifest> All => _manifests.Values.OrderBy(m => m.Key, StringComparer.Ordinal).ToList();

    public OAuthManifest? Get(string key) => _manifests.TryGetValue(key, out var m) ? m : null;

    public OAuthManifest? Get(Guid id) => _byId.TryGetValue(id, out var m) ? m : null;
}
