using System.Linq.Expressions;
using System.Text;
using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Persistence.Entities;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace DonkeyWork.Vault.Persistence;

public sealed class VaultDbContext : DbContext, IDataProtectionKeyContext
{
    private readonly IVaultCallerContext? _caller;

    public VaultDbContext(DbContextOptions<VaultDbContext> options, IVaultCallerContext? caller = null)
        : base(options)
    {
        _caller = caller;
    }

    /// <summary>Current caller's user id (Guid.Empty when unauthenticated / design-time).</summary>
    public Guid CurrentUserId => _caller?.UserId ?? Guid.Empty;

    public DbSet<ApiKeyEntity> ApiKeys => Set<ApiKeyEntity>();
    public DbSet<AccessKeyEntity> AccessKeys => Set<AccessKeyEntity>();
    public DbSet<OAuthProviderConfigEntity> OAuthProviderConfigs => Set<OAuthProviderConfigEntity>();
    public DbSet<OAuthTokenEntity> OAuthTokens => Set<OAuthTokenEntity>();
    public DbSet<ProviderManifestEntity> ProviderManifests => Set<ProviderManifestEntity>();
    public DbSet<OAuthStateEntity> OAuthStates => Set<OAuthStateEntity>();

    /// <summary>Append-only audit trail. Not a <c>BaseEntity</c>: no per-user filter, no update path.</summary>
    public DbSet<AuditLogEntity> AuditLogs => Set<AuditLogEntity>();

    public DbSet<DataProtectionKey> DataProtectionKeys => Set<DataProtectionKey>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.HasDefaultSchema("vault");
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(VaultDbContext).Assembly);

        // Global per-user row scoping on every BaseEntity-derived type.
        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        {
            if (typeof(BaseEntity).IsAssignableFrom(entityType.ClrType))
            {
                var e = Expression.Parameter(entityType.ClrType, "e");
                var body = Expression.Equal(
                    Expression.Property(e, nameof(BaseEntity.UserId)),
                    Expression.Property(Expression.Constant(this), nameof(CurrentUserId)));
                modelBuilder.Entity(entityType.ClrType).HasQueryFilter(Expression.Lambda(body, e));
            }
        }

        // snake_case all tables + columns (no external naming-convention package).
        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        {
            var table = entityType.GetTableName();
            if (table is not null)
            {
                entityType.SetTableName(ToSnakeCase(table));
            }

            foreach (var property in entityType.GetProperties())
            {
                property.SetColumnName(ToSnakeCase(property.Name));
            }
        }
    }

    private static string ToSnakeCase(string input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return input;
        }

        var sb = new StringBuilder(input.Length + 8);
        for (var i = 0; i < input.Length; i++)
        {
            var c = input[i];
            if (char.IsUpper(c))
            {
                if (i > 0 && (!char.IsUpper(input[i - 1]) || (i + 1 < input.Length && !char.IsUpper(input[i + 1]))))
                {
                    sb.Append('_');
                }
                sb.Append(char.ToLowerInvariant(c));
            }
            else
            {
                sb.Append(c);
            }
        }
        return sb.ToString();
    }
}
