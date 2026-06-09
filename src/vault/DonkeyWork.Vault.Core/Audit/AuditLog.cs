using System.Threading.Channels;
using DonkeyWork.Vault.Contracts.Audit;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace DonkeyWork.Vault.Core.Audit;

/// <summary>
/// Bounded, fire-and-forget audit sink. <see cref="Enqueue"/> writes to a bounded channel and
/// returns immediately; it never blocks and never throws to the caller. When the channel is full
/// (sustained DB outage / back-pressure) the event is dropped and a counter is incremented rather
/// than slowing the credential path — availability of the credential path is chosen over
/// guaranteed durability of every audit row. The <see cref="AuditLogWriter"/> drains the reader.
/// </summary>
public sealed class AuditLog : IAuditLog
{
    private readonly Channel<AuditEvent> _channel;
    private readonly ILogger<AuditLog> _logger;
    private long _dropped;

    public AuditLog(IOptions<AuditOptions> options, ILogger<AuditLog> logger)
    {
        _logger = logger;
        var capacity = Math.Max(1, options.Value.ChannelCapacity);
        _channel = Channel.CreateBounded<AuditEvent>(new BoundedChannelOptions(capacity)
        {
            // Wait mode + TryWrite never blocks: TryWrite returns false immediately when the buffer
            // is full, so we drop the event and count it rather than slowing the credential path.
            // (DropWrite would silently discard AND report success, hiding the drop from the metric.)
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false,
        });
    }

    /// <summary>Reader drained by the background writer.</summary>
    public ChannelReader<AuditEvent> Reader => _channel.Reader;

    /// <summary>Count of events dropped because the channel was full (back-pressure metric).</summary>
    public long DroppedCount => Interlocked.Read(ref _dropped);

    public void Enqueue(AuditEvent e)
    {
        try
        {
            if (!_channel.Writer.TryWrite(e))
            {
                var total = Interlocked.Increment(ref _dropped);
                // Log sparingly so a write outage doesn't itself become a log flood.
                if (total == 1 || total % 1000 == 0)
                {
                    _logger.LogWarning("Audit channel full; dropped {Dropped} event(s) so far.", total);
                }
            }
        }
        catch
        {
            // Auditing must never throw to the caller.
            Interlocked.Increment(ref _dropped);
        }
    }

    /// <summary>Signal that no more events will be written (graceful shutdown).</summary>
    public void Complete() => _channel.Writer.TryComplete();
}
