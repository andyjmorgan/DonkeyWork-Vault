using DonkeyWork.Vault.Contracts;

namespace DonkeyWork.Vault.Api.Identity;

/// <summary>
/// AsyncLocal-backed caller identity, set per gRPC call by <see cref="UserContextInterceptor"/>
/// and consumed by the service + DbContext query filter. Registered as a singleton; the
/// AsyncLocal makes it safe across concurrent calls.
/// </summary>
public sealed class VaultCallerContext : IVaultCallerContext
{
    private static readonly AsyncLocal<CallerInfo?> Current = new();

    public Guid UserId => Current.Value?.UserId ?? Guid.Empty;
    public Guid TenantId => Current.Value?.TenantId ?? Guid.Empty;

    public static void Set(Guid userId, Guid tenantId) => Current.Value = new CallerInfo(userId, tenantId);

    private sealed record CallerInfo(Guid UserId, Guid TenantId);
}
