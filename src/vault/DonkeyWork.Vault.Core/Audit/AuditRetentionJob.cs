using DonkeyWork.Vault.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace DonkeyWork.Vault.Core.Audit;

/// <summary>
/// Periodically deletes audit rows older than the configured hot-retention window
/// (<c>Vault:Audit:RetentionDays</c>, default 180) in batches, so the append-only table does not
/// grow without bound. Runs on its own scoped <see cref="VaultDbContext"/>. Batched delete keeps
/// the work off-peak-friendly; the window is fully config-driven.
/// </summary>
public sealed class AuditRetentionJob(
    IServiceScopeFactory scopeFactory,
    IOptions<AuditOptions> options,
    ILogger<AuditRetentionJob> logger) : BackgroundService
{
    private readonly AuditOptions _options = options.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var sweepEvery = TimeSpan.FromHours(Math.Max(1, _options.RetentionSweepHours));

        // Small initial delay so startup (migrations etc.) settles before the first sweep.
        try
        {
            await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await SweepAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Audit retention sweep failed; will retry next interval.");
            }

            try
            {
                await Task.Delay(sweepEvery, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private async Task SweepAsync(CancellationToken ct)
    {
        var retentionDays = Math.Max(1, _options.RetentionDays);
        var batchSize = Math.Max(1, _options.RetentionBatchSize);
        var cutoff = DateTimeOffset.UtcNow.AddDays(-retentionDays);

        long totalDeleted = 0;
        while (!ct.IsCancellationRequested)
        {
            using var scope = scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<VaultDbContext>();

            // Delete the oldest batch within the cutoff. ExecuteDelete keeps it set-based.
            var deleted = await db.AuditLogs
                .Where(a => a.CreatedAt < cutoff)
                .OrderBy(a => a.CreatedAt)
                .Take(batchSize)
                .ExecuteDeleteAsync(ct)
                .ConfigureAwait(false);

            totalDeleted += deleted;
            if (deleted < batchSize)
            {
                break;
            }
        }

        if (totalDeleted > 0)
        {
            logger.LogInformation("Audit retention removed {Count} row(s) older than {Days} days.", totalDeleted, retentionDays);
        }
    }
}
