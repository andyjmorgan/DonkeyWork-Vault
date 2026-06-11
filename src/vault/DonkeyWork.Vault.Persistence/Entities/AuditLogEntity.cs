using System.Net;

namespace DonkeyWork.Vault.Persistence.Entities;

/// <summary>
/// An append-only audit record of a credential-sensitive event. Deliberately <b>not</b> a
/// <see cref="BaseEntity"/>: the rows must never be updated, and read scoping is applied explicitly
/// by the audit query service. <c>UserId</c>/<c>TenantId</c> are plain columns. It never
/// stores secret material — the access key is referenced by id / prefix / name only (never the
/// <c>dwv_</c> secret nor its SHA-256 hash), and <c>Headers</c> is already redacted.
/// </summary>
public sealed class AuditLogEntity
{
    public Guid Id { get; set; }

    /// <summary>The <c>AuditEventType</c> (stored as int).</summary>
    public int EventType { get; set; }

    /// <summary>The <c>AuditOutcome</c> (0 = Success, 1 = Failure).</summary>
    public int Outcome { get; set; }

    /// <summary>Subject of the event; <see cref="Guid.Empty"/> when auth failed before identity resolved.</summary>
    public Guid UserId { get; set; }

    public Guid TenantId { get; set; }

    /// <summary>Reference to <c>access_keys.id</c>; null for internal-token / legacy / anonymous callers.</summary>
    public Guid? AccessKeyId { get; set; }

    /// <summary>Non-secret display reference, e.g. <c>dwv_AbCd</c>.</summary>
    public string? AccessKeyPrefix { get; set; }

    public string? AccessKeyName { get; set; }

    /// <summary>Resolved real client IP, mapped to Postgres <c>inet</c> natively; null when unknown.</summary>
    public IPAddress? SourceIp { get; set; }

    /// <summary>Redacted request headers (Postgres <c>jsonb</c>).</summary>
    public IReadOnlyDictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();

    /// <summary><c>oauth_token</c> / <c>api_key</c> / <c>access_key</c> / <c>provider_config</c>.</summary>
    public string? TargetKind { get; set; }

    public string? TargetProvider { get; set; }
    public string? TargetAccount { get; set; }
    public string? TargetName { get; set; }

    /// <summary><c>grpc</c> now; <c>http</c> after the transport migration.</summary>
    public string Transport { get; set; } = string.Empty;

    /// <summary>gRPC method or HTTP route, e.g. <c>/donkeywork.vault.v1.CredentialStore/GetApiKey</c>.</summary>
    public string? Method { get; set; }

    /// <summary>Failure reason, e.g. <c>missing scope 'vault:read'</c>.</summary>
    public string? Detail { get; set; }

    /// <summary>Event time (<c>now()</c>).</summary>
    public DateTimeOffset CreatedAt { get; set; }
}
