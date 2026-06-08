namespace DonkeyWork.Portal.Api.Auth;

/// <summary>
/// OIDC settings for the Portal. Bound from the <c>Oidc</c> config section, falling back to
/// the legacy <c>Keycloak</c> section (deprecated — kept for one release). Vendor-neutral:
/// any OIDC IdP that serves <c>.well-known/openid-configuration</c> works.
/// </summary>
public sealed class OidcOptions
{
    public const string SectionName = "Oidc";
    public const string LegacySectionName = "Keycloak";

    /// <summary>Public issuer URL used to validate the token issuer + by the SPA to log in
    /// (e.g. https://idp.example.com/realms/foo).</summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>Optional in-cluster issuer URL for metadata/JWKS retrieval (avoids DNS hairpin).</summary>
    public string? InternalAuthority { get; set; }

    /// <summary>Expected audience.</summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>Public client id the SPA uses to log in. Defaults to <see cref="Audience"/> if unset.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Space-separated scopes the SPA requests.</summary>
    public string Scopes { get; set; } = "openid profile email";

    public bool RequireHttpsMetadata { get; set; } = true;
}
