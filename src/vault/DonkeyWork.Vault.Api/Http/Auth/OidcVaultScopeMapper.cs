using System.Security.Claims;

namespace DonkeyWork.Vault.Api.Http.Auth;

public static class OidcVaultScopeMapper
{
    public static readonly string[] WebScopes = ["vault:read", "vault:readwrite", "vault:audit"];
    public static readonly string[] CliScopes = ["vault:read", "vault:readwrite"];

    public static IReadOnlyList<string> ScopesFor(ClaimsPrincipal principal, string webClientId, string cliClientId)
    {
        var clientId = ClientId(principal);
        if (string.Equals(clientId, cliClientId, StringComparison.Ordinal)
            && HasAudience(principal, webClientId))
        {
            return CliScopes;
        }
        if (string.Equals(clientId, webClientId, StringComparison.Ordinal))
        {
            return WebScopes;
        }
        return [];
    }

    public static string ClientId(ClaimsPrincipal principal)
    {
        if (principal.FindFirst("azp")?.Value is { Length: > 0 } azp)
        {
            return azp;
        }
        if (principal.FindFirst("client_id")?.Value is { Length: > 0 } clientId)
        {
            return clientId;
        }
        var audiences = principal.FindAll("aud").Select(c => c.Value).ToArray();
        return audiences.Length == 1 ? audiences[0] : string.Empty;
    }

    private static bool HasAudience(ClaimsPrincipal principal, string audience) =>
        !string.IsNullOrWhiteSpace(audience)
        && principal.FindAll("aud").Any(c => string.Equals(c.Value, audience, StringComparison.Ordinal));
}
