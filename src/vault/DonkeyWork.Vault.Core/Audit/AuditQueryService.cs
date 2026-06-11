using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Contracts.Audit;
using DonkeyWork.Vault.Persistence;
using Microsoft.EntityFrameworkCore;

namespace DonkeyWork.Vault.Core.Audit;

/// <summary>A single audit row projected for reading. Carries no secret material (the entity never did).</summary>
public sealed record AuditLogView(
    Guid Id,
    AuditEventType Type,
    AuditOutcome Outcome,
    Guid UserId,
    Guid TenantId,
    string? AccessKeyPrefix,
    string? AccessKeyName,
    string? SourceIp,
    string? TargetKind,
    string? TargetProvider,
    string? TargetAccount,
    string? TargetName,
    string Transport,
    string? Method,
    string? Detail,
    DateTimeOffset CreatedAt);

/// <summary>Filters for an audit query. Paging is clamped by the service.</summary>
public sealed record AuditQuery(
    int Limit = 50,
    int Offset = 0,
    AuditEventType? Type = null,
    AuditOutcome? Outcome = null,
    Guid? UserId = null,
    DateTimeOffset? Since = null,
    DateTimeOffset? Until = null);

public sealed record AuditQueryResult(IReadOnlyList<AuditLogView> Items, int Total, int Limit, int Offset);

public interface IAuditQueryService
{
    /// <summary>Reads the append-only audit trail (newest first) and records that the trail was accessed.</summary>
    Task<AuditQueryResult> QueryAsync(AuditQuery query, CancellationToken ct);
}

/// <summary>
/// Reads the append-only audit trail for the ambient caller. The table deliberately has no global
/// query filter because rows are append-only, so this service applies caller scoping explicitly.
/// Reading the trail is itself audited (<see cref="AuditEventType.AuditAccessed"/>).
/// </summary>
public sealed class AuditQueryService(VaultDbContext db, AuditEmitter audit, IVaultCallerContext caller) : IAuditQueryService
{
    public const int MaxLimit = 200;

    public async Task<AuditQueryResult> QueryAsync(AuditQuery query, CancellationToken ct)
    {
        var limit = Math.Clamp(query.Limit, 1, MaxLimit);
        var offset = Math.Max(0, query.Offset);

        var q = db.AuditLogs
            .AsNoTracking()
            .Where(a => a.UserId == caller.UserId && a.TenantId == caller.TenantId);

        if (query.Type is { } type)
        {
            q = q.Where(a => a.EventType == (int)type);
        }
        if (query.Outcome is { } outcome)
        {
            q = q.Where(a => a.Outcome == (int)outcome);
        }
        if (query.UserId is { } userId)
        {
            q = q.Where(a => a.UserId == userId);
        }
        if (query.Since is { } since)
        {
            q = q.Where(a => a.CreatedAt >= since);
        }
        if (query.Until is { } until)
        {
            q = q.Where(a => a.CreatedAt < until);
        }

        var total = await q.CountAsync(ct);

        // Materialise the page, then project in memory: IPAddress.ToString() and the int→enum casts
        // don't translate to SQL.
        var entities = await q
            .OrderByDescending(a => a.CreatedAt)
            .Skip(offset)
            .Take(limit)
            .ToListAsync(ct);

        var rows = entities.Select(a => new AuditLogView(
            a.Id,
            (AuditEventType)a.EventType,
            (AuditOutcome)a.Outcome,
            a.UserId,
            a.TenantId,
            a.AccessKeyPrefix,
            a.AccessKeyName,
            a.SourceIp?.ToString(),
            a.TargetKind,
            a.TargetProvider,
            a.TargetAccount,
            a.TargetName,
            a.Transport,
            a.Method,
            a.Detail,
            a.CreatedAt)).ToList();

        // Reading the trail is itself a credential-sensitive event.
        audit.Emit(AuditEventType.AuditAccessed, AuditOutcome.Success, targetKind: "audit_log");

        return new AuditQueryResult(rows, total, limit, offset);
    }
}
