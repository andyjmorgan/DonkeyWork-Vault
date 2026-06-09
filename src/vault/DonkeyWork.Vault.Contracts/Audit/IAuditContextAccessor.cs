namespace DonkeyWork.Vault.Contracts.Audit;

/// <summary>
/// Per-request audit metadata, resolved once by the transport populator (the gRPC interceptor
/// today, an HTTP middleware later) and read by the domain services when they emit events. The
/// headers it carries are already redacted; the access key is referenced by id / prefix / name
/// only. Empty/default when no request is in scope (e.g. background work).
/// </summary>
public sealed record AuditRequestInfo(
    string? SourceIp,
    IReadOnlyDictionary<string, string> Headers,
    Guid? AccessKeyId,
    string? AccessKeyPrefix,
    string? AccessKeyName,
    string Transport,
    string? Method)
{
    public static readonly AuditRequestInfo Empty = new(
        SourceIp: null,
        Headers: new Dictionary<string, string>(),
        AccessKeyId: null,
        AccessKeyPrefix: null,
        AccessKeyName: null,
        Transport: "unknown",
        Method: null);
}

/// <summary>
/// AsyncLocal-backed ambient accessor for the current request's audit metadata. Same pattern as
/// the caller-identity context; safe across concurrent calls. The populator calls
/// <see cref="Set"/>; domain services read <see cref="Current"/>.
/// </summary>
public interface IAuditContextAccessor
{
    /// <summary>The current request's audit metadata, or <see cref="AuditRequestInfo.Empty"/>.</summary>
    AuditRequestInfo Current { get; }

    /// <summary>Publish the resolved metadata for the in-flight request.</summary>
    void Set(AuditRequestInfo info);
}
