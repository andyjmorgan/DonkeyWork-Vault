using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Contracts.Audit;

namespace DonkeyWork.Vault.Core.Audit;

/// <summary>
/// Convenience wrapper that builds an <see cref="AuditEvent"/> from the ambient request context
/// (<see cref="IAuditContextAccessor"/>) and the caller identity, leaving the domain service to
/// supply only the event-specific fields. Fire-and-forget: it reads ambient state and enqueues;
/// it never blocks or throws on the credential path.
/// </summary>
public sealed class AuditEmitter(IAuditLog auditLog, IAuditContextAccessor context, IVaultCallerContext caller)
{
    /// <summary>
    /// Emit an event. <paramref name="userId"/>/<paramref name="tenantId"/> default to the ambient
    /// caller when not supplied (the anonymous OAuth callback passes them explicitly from the
    /// state row, since no caller identity exists there).
    /// </summary>
    public void Emit(
        AuditEventType type,
        AuditOutcome outcome,
        string? targetKind = null,
        string? targetProvider = null,
        string? targetAccount = null,
        string? targetName = null,
        string? detail = null,
        Guid? userId = null,
        Guid? tenantId = null)
    {
        var info = context.Current;
        var e = new AuditEvent(
            Type: type,
            Outcome: outcome,
            UserId: userId ?? caller.UserId,
            TenantId: tenantId ?? caller.TenantId,
            AccessKeyId: info.AccessKeyId,
            AccessKeyPrefix: info.AccessKeyPrefix,
            AccessKeyName: info.AccessKeyName,
            SourceIp: info.SourceIp,
            Headers: info.Headers,
            TargetKind: targetKind,
            TargetProvider: targetProvider,
            TargetAccount: targetAccount,
            TargetName: targetName,
            Transport: info.Transport,
            Method: info.Method,
            Detail: detail,
            CreatedAt: DateTimeOffset.UtcNow);
        auditLog.Enqueue(e);
    }
}
