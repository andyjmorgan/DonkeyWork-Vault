using System.Text.Json;

namespace DonkeyWork.Vault.Core.Manifests;

/// <summary>Fetches an OIDC `.well-known/openid-configuration` and maps it to a draft manifest.</summary>
public sealed class OAuthDiscoveryService(IHttpClientFactory httpFactory)
{
    public async Task<OAuthManifest> DiscoverAsync(string url, CancellationToken ct)
    {
        var u = url.Trim();
        if (!u.Contains("/.well-known/", StringComparison.OrdinalIgnoreCase))
        {
            u = u.TrimEnd('/') + "/.well-known/openid-configuration";
        }

        var client = httpFactory.CreateClient("oauth");
        using var req = new HttpRequestMessage(HttpMethod.Get, u);
        req.Headers.TryAddWithoutValidation("Accept", "application/json");
        req.Headers.TryAddWithoutValidation("User-Agent", "donkeywork-vault");
        using var resp = await client.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        var r = doc.RootElement;
        string S(string k) => r.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : string.Empty;

        var m = new OAuthManifest
        {
            AuthorizationEndpoint = S("authorization_endpoint"),
            TokenEndpoint = S("token_endpoint"),
            UserinfoEndpoint = S("userinfo_endpoint"),
            ScopeDelimiter = " ",
        };

        var issuer = S("issuer");
        if (!string.IsNullOrEmpty(issuer) && Uri.TryCreate(issuer, UriKind.Absolute, out var iu))
        {
            m.Name = NormalizeHost(iu.Host);
            m.Key = KeyFromHost(iu.Host);
        }

        if (r.TryGetProperty("scopes_supported", out var ss) && ss.ValueKind == JsonValueKind.Array)
        {
            foreach (var s in ss.EnumerateArray())
            {
                if (s.ValueKind == JsonValueKind.String && s.GetString() is { Length: > 0 } val)
                {
                    m.Scopes.Add(new OAuthScopeDef { Value = val, Category = "discovered" });
                    if (val is "openid" or "email" or "profile" or "offline_access")
                    {
                        m.DefaultScopes.Add(val);
                    }
                }
            }
        }

        return m;
    }

    /// <summary>Host without a leading <c>www.</c>, lower-cased (e.g. <c>www.dropbox.com</c> → <c>dropbox.com</c>).</summary>
    public static string NormalizeHost(string host)
    {
        var h = host.Trim().TrimEnd('.').ToLowerInvariant();
        return h.StartsWith("www.", StringComparison.Ordinal) ? h["www.".Length..] : h;
    }

    /// <summary>
    /// Derives a short provider key from an issuer host: the registrable label, i.e. the
    /// second-to-last label after dropping a leading <c>www.</c> — <c>www.dropbox.com</c> → <c>dropbox</c>,
    /// <c>accounts.google.com</c> → <c>google</c>. Single-label hosts return as-is. (A user can edit it.)
    /// </summary>
    public static string KeyFromHost(string host)
    {
        var labels = NormalizeHost(host).Split('.', StringSplitOptions.RemoveEmptyEntries);
        return labels.Length switch
        {
            0 => string.Empty,
            1 => labels[0],
            _ => labels[^2],
        };
    }
}
