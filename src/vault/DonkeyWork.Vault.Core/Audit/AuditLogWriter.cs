using System.Diagnostics;
using System.Net;
using DonkeyWork.Vault.Contracts.Audit;
using DonkeyWork.Vault.Persistence;
using DonkeyWork.Vault.Persistence.Entities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace DonkeyWork.Vault.Core.Audit;

/// <summary>
/// Drains the <see cref="AuditLog"/> channel and bulk-inserts batched events into a <b>fresh
/// scoped</b> <see cref="VaultDbContext"/> — never the request's context — so writes never block
/// the credential hot path and the per-user query filter is irrelevant (we only insert here).
/// On DB failure it retries with backoff and, as a last resort, drops the batch with a structured
/// log line rather than wedging the channel. Flushes remaining events on graceful shutdown.
/// </summary>
public sealed class AuditLogWriter(
    AuditLog auditLog,
    IServiceScopeFactory scopeFactory,
    IOptions<AuditOptions> options,
    ILogger<AuditLogWriter> logger) : BackgroundService
{
    private readonly AuditOptions _options = options.Value;

    // The host's shutdown token, captured in StopAsync so the final drain is bounded by the
    // shutdown deadline rather than able to hang the process on a stuck DB write.
    private CancellationToken _shutdownToken = CancellationToken.None;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var batchSize = Math.Max(1, _options.BatchSize);
        var flushInterval = TimeSpan.FromMilliseconds(Math.Max(1, _options.FlushIntervalMs));
        var reader = auditLog.Reader;
        var batch = new List<AuditEvent>(batchSize);

        try
        {
            // Block until at least one event is available, then greedily fill the batch up to
            // batchSize or the flush window, whichever comes first.
            while (await reader.WaitToReadAsync(stoppingToken).ConfigureAwait(false))
            {
                batch.Clear();
                var deadline = Stopwatch.GetTimestamp() + (long)(flushInterval.TotalSeconds * Stopwatch.Frequency);
                while (batch.Count < batchSize && reader.TryRead(out var e))
                {
                    batch.Add(e);
                    if (Stopwatch.GetTimestamp() >= deadline)
                    {
                        break;
                    }
                }

                if (batch.Count > 0)
                {
                    await PersistWithRetryAsync(batch, stoppingToken).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Shutdown requested — fall through to the final drain below.
        }

        await DrainOnShutdownAsync().ConfigureAwait(false);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        // Bound the final drain by the host shutdown deadline, then stop accepting new events.
        _shutdownToken = cancellationToken;
        auditLog.Complete();
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task DrainOnShutdownAsync()
    {
        try
        {
            var remaining = new List<AuditEvent>();
            while (auditLog.Reader.TryRead(out var e))
            {
                remaining.Add(e);
            }
            if (remaining.Count > 0)
            {
                await PersistWithRetryAsync(remaining, _shutdownToken).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to flush audit events on shutdown ({Count} lost).", auditLog.Reader.Count);
        }
    }

    private async Task PersistWithRetryAsync(IReadOnlyList<AuditEvent> batch, CancellationToken ct)
    {
        const int maxAttempts = 4;
        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<VaultDbContext>();
                foreach (var e in batch)
                {
                    db.AuditLogs.Add(ToEntity(e));
                }
                await db.SaveChangesAsync(ct).ConfigureAwait(false);
                return;
            }
            catch (Exception ex) when (attempt < maxAttempts && !ct.IsCancellationRequested)
            {
                var delay = TimeSpan.FromMilliseconds(200 * Math.Pow(2, attempt - 1));
                logger.LogWarning(ex, "Audit batch insert failed (attempt {Attempt}/{Max}); retrying in {Delay}ms.",
                    attempt, maxAttempts, delay.TotalMilliseconds);
                try
                {
                    await Task.Delay(delay, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
            catch (Exception ex)
            {
                // Last resort: do not wedge the channel. Emit the (already redacted) events to the
                // structured log so the trail is not silently lost, then drop the batch.
                logger.LogError(ex, "Audit batch insert failed permanently; dropping {Count} event(s).", batch.Count);
                foreach (var e in batch)
                {
                    logger.LogWarning(
                        "AUDIT(unpersisted) type={Type} outcome={Outcome} user={User} key={KeyPrefix} ip={Ip} target={TargetKind}:{TargetName} method={Method} detail={Detail}",
                        e.Type, e.Outcome, e.UserId, e.AccessKeyPrefix, e.SourceIp, e.TargetKind, e.TargetName, e.Method, e.Detail);
                }
                return;
            }
        }
    }

    private static AuditLogEntity ToEntity(AuditEvent e) => new()
    {
        EventType = (int)e.Type,
        Outcome = (int)e.Outcome,
        UserId = e.UserId,
        TenantId = e.TenantId,
        AccessKeyId = e.AccessKeyId,
        AccessKeyPrefix = e.AccessKeyPrefix,
        AccessKeyName = e.AccessKeyName,
        SourceIp = ParseIp(e.SourceIp),
        Headers = e.Headers,
        TargetKind = e.TargetKind,
        TargetProvider = e.TargetProvider,
        TargetAccount = e.TargetAccount,
        TargetName = e.TargetName,
        Transport = e.Transport,
        Method = e.Method,
        Detail = e.Detail,
        CreatedAt = e.CreatedAt,
    };

    private static IPAddress? ParseIp(string? value) =>
        !string.IsNullOrWhiteSpace(value) && IPAddress.TryParse(value, out var ip) ? ip : null;
}
