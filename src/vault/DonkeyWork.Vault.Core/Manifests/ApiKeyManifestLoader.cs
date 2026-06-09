using System.Reflection;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace DonkeyWork.Vault.Core.Manifests;

/// <summary>
/// Loads + validates any embedded API-key provider catalog at construction (singleton). The catalog
/// is normally empty — API-key/header credentials are provided generically (arbitrary header/prefix),
/// so there are no built-in API-key providers (built-in providers are OAuth-only). A malformed
/// manifest still fails fast. DB-stored manifests can add entries at runtime.
/// </summary>
public sealed class ApiKeyManifestLoader
{
    private readonly IReadOnlyDictionary<string, ApiKeyManifest> _manifests;

    public ApiKeyManifestLoader()
    {
        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();

        var asm = typeof(ApiKeyManifestLoader).Assembly;
        var dict = new Dictionary<string, ApiKeyManifest>(StringComparer.OrdinalIgnoreCase);

        foreach (var resource in asm.GetManifestResourceNames()
                     .Where(n => n.Contains(".Embedded.apikey.") && n.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase)))
        {
            using var stream = asm.GetManifestResourceStream(resource)!;
            using var reader = new StreamReader(stream);
            var manifest = deserializer.Deserialize<ApiKeyManifest>(reader)
                ?? throw new InvalidOperationException($"Manifest '{resource}' deserialized to null.");

            Validate(manifest, resource);
            dict[manifest.Key] = manifest;
        }

        // An empty catalog is valid: there are no built-in API-key providers by default.
        _manifests = dict;
    }

    public IReadOnlyList<ApiKeyManifest> All => _manifests.Values.OrderBy(m => m.Key, StringComparer.Ordinal).ToList();

    public ApiKeyManifest? Get(string key) => _manifests.TryGetValue(key, out var m) ? m : null;

    private static void Validate(ApiKeyManifest m, string resource)
    {
        if (string.IsNullOrWhiteSpace(m.Key))
        {
            throw new InvalidOperationException($"Manifest '{resource}' is missing 'key'.");
        }
        if (m.Auth.Scheme is not ("header" or "basic"))
        {
            throw new InvalidOperationException($"Manifest '{m.Key}': auth.scheme must be 'header' or 'basic'.");
        }
        if (m.Fields.Count == 0)
        {
            throw new InvalidOperationException($"Manifest '{m.Key}': must declare at least one field.");
        }
    }
}
