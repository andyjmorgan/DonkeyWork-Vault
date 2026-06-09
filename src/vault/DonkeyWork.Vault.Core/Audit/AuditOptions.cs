namespace DonkeyWork.Vault.Core.Audit;

/// <summary>
/// Configuration for the audit subsystem, bound from <c>Vault:Audit</c>.
/// </summary>
public sealed class AuditOptions
{
    public const string SectionName = "Vault:Audit";

    /// <summary>Bounded channel capacity. When full, new events are dropped (and counted).</summary>
    public int ChannelCapacity { get; set; } = 8192;

    /// <summary>Max events per batched insert.</summary>
    public int BatchSize { get; set; } = 100;

    /// <summary>Max time to accumulate a partial batch before flushing, in milliseconds.</summary>
    public int FlushIntervalMs { get; set; } = 500;

    /// <summary>Hot-retention window in days; rows older than this are deleted by the retention job.</summary>
    public int RetentionDays { get; set; } = 180;

    /// <summary>How often the retention sweep runs, in hours.</summary>
    public int RetentionSweepHours { get; set; } = 12;

    /// <summary>Rows deleted per retention batch (keeps the delete off the hot path).</summary>
    public int RetentionBatchSize { get; set; } = 5000;

    /// <summary>
    /// Trusted proxy CIDRs (ingress / Service / lab subnets). Forwarded headers are honoured only
    /// when the immediate peer is within one of these. Empty ⇒ never trust forwarded headers.
    /// </summary>
    public List<string> TrustedProxies { get; set; } = new();
}
