namespace DonkeyWork.Vault.Contracts;

/// <summary>
/// Ambient caller identity for a vault request, populated from gRPC metadata
/// (x-user-id / x-tenant-id). Drives row scoping. TenantId is carried now but not
/// enforced (single-tenant for Objective 1).
/// </summary>
public interface IVaultCallerContext
{
    Guid UserId { get; }
    Guid TenantId { get; }
}
