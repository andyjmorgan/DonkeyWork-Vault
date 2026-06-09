using DonkeyWork.Vault.Contracts.Audit;

namespace DonkeyWork.Vault.Core.Audit;

/// <summary>
/// AsyncLocal-backed implementation of <see cref="IAuditContextAccessor"/> — same pattern as the
/// caller-identity context. Registered as a singleton; the AsyncLocal makes it safe across
/// concurrent requests. The transport populator sets it; domain services read it.
/// </summary>
public sealed class AuditContextAccessor : IAuditContextAccessor
{
    private static readonly AsyncLocal<AuditRequestInfo?> Value = new();

    public AuditRequestInfo Current => Value.Value ?? AuditRequestInfo.Empty;

    public void Set(AuditRequestInfo info) => Value.Value = info;
}
