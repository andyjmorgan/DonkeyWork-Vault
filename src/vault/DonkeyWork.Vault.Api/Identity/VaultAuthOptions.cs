namespace DonkeyWork.Vault.Api.Identity;

/// <summary>
/// Vault authentication configuration (section "Vault:Auth").
/// </summary>
public sealed class VaultAuthOptions
{
    public const string SectionName = "Vault:Auth";

    /// <summary>
    /// Shared secret proving a call comes from the trusted Portal BFF (the in-cluster hop).
    /// When a request presents a matching <c>x-internal-token</c>, the vault trusts the
    /// accompanying <c>x-user-id</c>/<c>x-tenant-id</c>. Empty disables the internal-hop path.
    /// </summary>
    public string? InternalToken { get; set; }

    /// <summary>
    /// When true, the vault trusts a bare <c>x-user-id</c> with NO credential. This is the
    /// legacy/on-prem model — acceptable only on a fully trusted network. Off by default;
    /// internet-facing deployments must use API keys (or the internal token for the Portal).
    /// </summary>
    public bool AllowUnauthenticatedUserId { get; set; }
}
