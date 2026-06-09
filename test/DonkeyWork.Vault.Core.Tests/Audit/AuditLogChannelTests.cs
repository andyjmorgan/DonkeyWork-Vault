using DonkeyWork.Vault.Contracts.Audit;
using DonkeyWork.Vault.Core.Audit;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace DonkeyWork.Vault.Core.Tests.Audit;

public class AuditLogChannelTests
{
    private static AuditEvent SampleEvent() => new(
        AuditEventType.TokenAccessed, AuditOutcome.Success,
        UserId: Guid.NewGuid(), TenantId: Guid.Empty,
        AccessKeyId: null, AccessKeyPrefix: null, AccessKeyName: null,
        SourceIp: "203.0.113.1", Headers: new Dictionary<string, string>(),
        TargetKind: "api_key", TargetProvider: null, TargetAccount: null, TargetName: "grafana",
        Transport: "grpc", Method: "/x/Get", Detail: null, CreatedAt: DateTimeOffset.UtcNow);

    private static AuditLog NewLog(int capacity)
    {
        var opts = Options.Create(new AuditOptions { ChannelCapacity = capacity });
        return new AuditLog(opts, NullLogger<AuditLog>.Instance);
    }

    [Fact]
    public void Enqueue_WhenChannelFull_DropsAndCountsRatherThanThrows()
    {
        var log = NewLog(capacity: 4);

        // Nothing drains the reader, so after capacity is reached every write is dropped.
        var exception = Record.Exception(() =>
        {
            for (var i = 0; i < 1000; i++)
            {
                log.Enqueue(SampleEvent());
            }
        });

        Assert.Null(exception);                 // never throws to the caller
        Assert.True(log.DroppedCount > 0);      // drops are counted
        Assert.Equal(1000 - 4, log.DroppedCount); // exactly the overflow was dropped
    }

    [Fact]
    public async Task Enqueue_WithinCapacity_AllEventsReadable()
    {
        var log = NewLog(capacity: 16);

        for (var i = 0; i < 10; i++)
        {
            log.Enqueue(SampleEvent());
        }

        Assert.Equal(0, log.DroppedCount);

        var read = 0;
        while (log.Reader.TryRead(out _))
        {
            read++;
        }
        Assert.Equal(10, read);
        await Task.CompletedTask;
    }
}
