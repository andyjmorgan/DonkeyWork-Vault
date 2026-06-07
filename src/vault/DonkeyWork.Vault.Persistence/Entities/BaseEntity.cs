namespace DonkeyWork.Vault.Persistence.Entities;

/// <summary>
/// Base for all vault rows. Carries UserId (enforced via a global query filter) and
/// TenantId (present + indexed but NOT filtered yet — single-tenant for Objective 1, so
/// multi-tenant becomes a later epic rather than a schema migration). Optimistic
/// concurrency is provided by Postgres xmin (configured per entity), not a column here.
/// </summary>
public abstract class BaseEntity
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public Guid TenantId { get; set; } = Guid.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? UpdatedAt { get; set; }
}
