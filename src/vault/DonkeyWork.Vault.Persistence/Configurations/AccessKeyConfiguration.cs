using DonkeyWork.Vault.Persistence.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace DonkeyWork.Vault.Persistence.Configurations;

public sealed class AccessKeyConfiguration : IEntityTypeConfiguration<AccessKeyEntity>
{
    public void Configure(EntityTypeBuilder<AccessKeyEntity> b)
    {
        b.ToTable("access_keys");
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasDefaultValueSql("gen_random_uuid()");
        b.Property(x => x.Name).HasMaxLength(255).IsRequired();
        b.Property(x => x.Description).HasMaxLength(1024);
        b.Property(x => x.KeyHash).HasColumnType("bytea").IsRequired();
        b.Property(x => x.KeyPrefix).HasMaxLength(32).IsRequired();
        b.Property(x => x.Scopes).HasColumnType("text[]").IsRequired();
        b.Property(x => x.Enabled).HasDefaultValue(true);
        b.Property(x => x.CreatedAt).HasDefaultValueSql("now()");

        // Global lookup index: authentication resolves a key by hash before the caller is known
        // (the per-user query filter is bypassed for that path), so the hash must be unique estate-wide.
        b.HasIndex(x => x.KeyHash).IsUnique();
        b.HasIndex(x => new { x.UserId, x.Name }).IsUnique();
        b.HasIndex(x => new { x.TenantId, x.UserId });
    }
}
