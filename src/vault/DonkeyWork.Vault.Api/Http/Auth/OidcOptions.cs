namespace DonkeyWork.Vault.Api.Http.Auth;

/// <summary>
/// OIDC settings for the vault's interactive (human) auth. Bound from the <c>Oidc</c> config section,
/// falling back to the legacy <c>Keycloak</c> section (deprecated). Vendor-neutral: any OIDC IdP that
/// serves <c>.well-known/openid-configuration</c> works. Machine callers use <c>dwv_</c> access keys
/// instead and do not touch this.
/// </summary>
public sealed class OidcOptions
{
    public const string SectionName = "Oidc";
    public const string LegacySectionName = "Keycloak";

    /// <summary>Public issuer URL used to validate the token issuer + by the SPA to log in.</summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>Optional in-cluster issuer URL for metadata/JWKS retrieval (avoids DNS hairpin).</summary>
    public string? InternalAuthority { get; set; }

    /// <summary>Expected audience.</summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>Legacy public client id the SPA uses to log in. Prefer <see cref="WebClientId"/>.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Public client id the web UI uses to log in. Defaults to <see cref="ClientId"/>, then <see cref="Audience"/>.</summary>
    public string WebClientId { get; set; } = string.Empty;

    /// <summary>Public client id the CLI uses for OAuth device authorization.</summary>
    public string CliClientId { get; set; } = string.Empty;

    /// <summary>Legacy space-separated scopes the SPA requests. Prefer <see cref="WebScopes"/>.</summary>
    public string Scopes { get; set; } = "openid profile email";

    /// <summary>Space-separated scopes the web UI requests.</summary>
    public string WebScopes { get; set; } = string.Empty;

    /// <summary>Space-separated scopes the CLI requests during device authorization.</summary>
    public string CliScopes { get; set; } = "openid profile email offline_access";

    public bool RequireHttpsMetadata { get; set; } = true;

    public string EffectiveWebClientId =>
        FirstNonEmpty(WebClientId, ClientId, Audience);

    public string EffectiveWebScopes =>
        FirstNonEmpty(WebScopes, Scopes, "openid profile email");

    public string EffectiveCliClientId =>
        FirstNonEmpty(CliClientId, "donkeywork-vault-cli");

    public string EffectiveCliScopes =>
        FirstNonEmpty(CliScopes, "openid profile email offline_access");

    private static string FirstNonEmpty(params string[] values) =>
        values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v)) ?? string.Empty;
}
