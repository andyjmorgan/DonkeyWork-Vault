using DonkeyWork.Vault.Persistence.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace DonkeyWork.Vault.Persistence.Configurations;

public sealed class ProviderManifestConfiguration : IEntityTypeConfiguration<ProviderManifestEntity>
{
    public void Configure(EntityTypeBuilder<ProviderManifestEntity> b)
    {
        b.ToTable("provider_manifests");
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasDefaultValueSql("gen_random_uuid()");
        b.Property(x => x.Kind).HasMaxLength(20).IsRequired();
        b.Property(x => x.Key).HasMaxLength(100).IsRequired();
        b.Property(x => x.DocumentJson).HasColumnType("jsonb").IsRequired();
        b.Property(x => x.CreatedAt).HasDefaultValueSql("now()");
        b.HasIndex(x => new { x.TenantId, x.Kind, x.Key }).IsUnique();
    }
}

public sealed class OAuthStateConfiguration : IEntityTypeConfiguration<OAuthStateEntity>
{
    public void Configure(EntityTypeBuilder<OAuthStateEntity> b)
    {
        b.ToTable("oauth_states");
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasDefaultValueSql("gen_random_uuid()");
        b.Property(x => x.State).HasMaxLength(128).IsRequired();
        b.Property(x => x.Provider).HasMaxLength(100).IsRequired();
        b.Property(x => x.CodeVerifier).HasMaxLength(256).IsRequired();
        b.Property(x => x.RedirectUri).HasMaxLength(512).IsRequired();
        b.Property(x => x.CreatedAt).HasDefaultValueSql("now()");
        b.HasIndex(x => x.State).IsUnique();
        b.HasIndex(x => x.ExpiresAt);
    }
}
