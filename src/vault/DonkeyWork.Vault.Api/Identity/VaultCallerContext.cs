using DonkeyWork.Vault.Contracts;

namespace DonkeyWork.Vault.Api.Identity;

/// <summary>
/// AsyncLocal-backed caller identity, set per request by the <c>AuditContextMiddleware</c> from the
/// authenticated principal and consumed by the domain services + the DbContext per-user query filter.
/// Registered as a singleton; the AsyncLocal makes it safe across concurrent requests.
/// </summary>
public sealed class VaultCallerContext : IVaultCallerContext
{
    private static readonly AsyncLocal<CallerInfo?> Current = new();

    public Guid UserId => Current.Value?.UserId ?? Guid.Empty;
    public Guid TenantId => Current.Value?.TenantId ?? Guid.Empty;

    public static void Set(Guid userId, Guid tenantId) => Current.Value = new CallerInfo(userId, tenantId);

    private sealed record CallerInfo(Guid UserId, Guid TenantId);
}
