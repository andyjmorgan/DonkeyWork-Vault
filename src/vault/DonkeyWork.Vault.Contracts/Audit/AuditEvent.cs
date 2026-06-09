namespace DonkeyWork.Vault.Contracts.Audit;

/// <summary>Whether the audited operation succeeded or failed.</summary>
public enum AuditOutcome
{
    Success = 0,
    Failure = 1,
}

/// <summary>
/// An immutable, append-only audit record. Built by the domain services (target fields) and the
/// request populator (<see cref="IAuditContextAccessor"/> supplies IP / redacted headers / key
/// reference / transport / method). It carries <b>no</b> secret material: the access key is
/// referenced by id / prefix / name only, never the <c>dwv_</c> secret nor its hash, and the
/// headers are already redacted before they reach this record.
/// </summary>
public sealed record AuditEvent(
    AuditEventType Type,
    AuditOutcome Outcome,
    Guid UserId,
    Guid TenantId,
    Guid? AccessKeyId,
    string? AccessKeyPrefix,
    string? AccessKeyName,
    string? SourceIp,
    IReadOnlyDictionary<string, string> Headers,
    string? TargetKind,
    string? TargetProvider,
    string? TargetAccount,
    string? TargetName,
    string Transport,
    string? Method,
    string? Detail,
    DateTimeOffset CreatedAt);
