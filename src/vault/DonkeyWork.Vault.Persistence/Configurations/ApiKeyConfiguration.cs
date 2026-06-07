using DonkeyWork.Vault.Persistence.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace DonkeyWork.Vault.Persistence.Configurations;

public sealed class ApiKeyConfiguration : IEntityTypeConfiguration<ApiKeyEntity>
{
    public void Configure(EntityTypeBuilder<ApiKeyEntity> b)
    {
        b.ToTable("api_keys");
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasDefaultValueSql("gen_random_uuid()");
        b.Property(x => x.ProviderKey).HasMaxLength(100).IsRequired();
        b.Property(x => x.Name).HasMaxLength(255).IsRequired();
        b.Property(x => x.FieldsCipher).HasColumnType("bytea").IsRequired();
        b.Property(x => x.CreatedAt).HasDefaultValueSql("now()");

        b.HasIndex(x => new { x.UserId, x.ProviderKey, x.Name }).IsUnique();
        b.HasIndex(x => new { x.TenantId, x.UserId });

        // TODO(task 6): add Postgres xmin optimistic-concurrency token when wiring
        // the OAuth refresh job / provider-config edits.
    }
}
