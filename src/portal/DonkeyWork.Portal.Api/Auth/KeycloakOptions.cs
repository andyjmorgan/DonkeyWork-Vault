namespace DonkeyWork.Portal.Api.Auth;

public sealed class KeycloakOptions
{
    public const string SectionName = "Keycloak";

    /// <summary>External realm URL used to validate the token issuer (e.g. https://auth.../realms/Agents).</summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>Optional in-cluster URL for metadata/JWKS retrieval (avoids DNS hairpin).</summary>
    public string? InternalAuthority { get; set; }

    /// <summary>Expected audience / client id.</summary>
    public string Audience { get; set; } = string.Empty;

    public bool RequireHttpsMetadata { get; set; } = true;
}
