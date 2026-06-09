namespace DonkeyWork.Vault.Contracts.Audit;

/// <summary>
/// Fire-and-forget sink for audit events. <see cref="Enqueue"/> is non-blocking and never throws
/// to the caller — auditing must never slow or fail the credential path. The event is buffered and
/// written out-of-band by a background writer on its own <c>DbContext</c>, never the request's.
/// </summary>
public interface IAuditLog
{
    /// <summary>Buffer an event for background persistence. Never blocks; never throws.</summary>
    void Enqueue(AuditEvent e);
}
