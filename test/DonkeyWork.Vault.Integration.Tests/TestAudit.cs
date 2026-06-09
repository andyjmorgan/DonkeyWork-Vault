using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Contracts.Audit;
using DonkeyWork.Vault.Core.Audit;

namespace DonkeyWork.Vault.Integration.Tests;

/// <summary>An <see cref="IAuditLog"/> that captures enqueued events for assertions.</summary>
public sealed class CapturingAuditLog : IAuditLog
{
    private readonly List<AuditEvent> _events = new();

    public IReadOnlyList<AuditEvent> Events
    {
        get
        {
            lock (_events)
            {
                return _events.ToList();
            }
        }
    }

    public void Enqueue(AuditEvent e)
    {
        lock (_events)
        {
            _events.Add(e);
        }
    }
}

/// <summary>An accessor that always returns a fixed request info (or Empty).</summary>
public sealed class FixedAuditContext(AuditRequestInfo? info = null) : IAuditContextAccessor
{
    private AuditRequestInfo _info = info ?? AuditRequestInfo.Empty;

    public AuditRequestInfo Current => _info;

    public void Set(AuditRequestInfo i) => _info = i;
}

/// <summary>Test factory for an <see cref="AuditEmitter"/> over a capturing sink.</summary>
public static class TestAudit
{
    public static (AuditEmitter emitter, CapturingAuditLog log) Build(
        IVaultCallerContext caller, AuditRequestInfo? info = null)
    {
        var log = new CapturingAuditLog();
        var emitter = new AuditEmitter(log, new FixedAuditContext(info), caller);
        return (emitter, log);
    }
}
