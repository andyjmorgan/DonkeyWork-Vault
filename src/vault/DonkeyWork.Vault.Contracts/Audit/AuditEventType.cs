namespace DonkeyWork.Vault.Contracts.Audit;

/// <summary>
/// The kind of credential-sensitive event recorded in the append-only audit trail.
/// Stored as <see cref="int"/>; values are stable and must not be reordered.
/// </summary>
public enum AuditEventType
{
    Unknown = 0,

    /// <summary>A credential / OAuth access token was read or revealed.</summary>
    TokenAccessed = 1,

    /// <summary>A refresh-grant produced a new access token.</summary>
    TokenRefreshed = 2,

    /// <summary>An OAuth flow completed and a token row was stored.</summary>
    TokenAdded = 3,

    /// <summary>An API key / access key / provider config was created.</summary>
    CredentialCreated = 4,

    /// <summary>An access key authenticated successfully.</summary>
    AuthSucceeded = 5,

    /// <summary>Authentication or authorization failed.</summary>
    AuthFailed = 6,

    /// <summary>Someone read the audit log itself.</summary>
    AuditAccessed = 7,

    /// <summary>A stored OAuth token (connected account) was deleted.</summary>
    TokenRemoved = 8,
}
