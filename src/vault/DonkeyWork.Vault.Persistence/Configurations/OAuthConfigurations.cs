using DonkeyWork.Vault.Persistence.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace DonkeyWork.Vault.Persistence.Configurations;

public sealed class OAuthProviderConfigConfiguration : IEntityTypeConfiguration<OAuthProviderConfigEntity>
{
    public void Configure(EntityTypeBuilder<OAuthProviderConfigEntity> b)
    {
        b.ToTable("oauth_provider_configs");
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasDefaultValueSql("gen_random_uuid()");
        b.Property(x => x.ProviderKey).HasMaxLength(100).IsRequired();
        b.Property(x => x.ClientIdCipher).HasColumnType("bytea").IsRequired();
        b.Property(x => x.ClientSecretCipher).HasColumnType("bytea").IsRequired();
        b.Property(x => x.ScopesJson).HasColumnType("jsonb");
        b.Property(x => x.CreatedAt).HasDefaultValueSql("now()");
        // Identity, not the (renameable) slug, is the uniqueness + lookup key.
        b.HasIndex(x => new { x.UserId, x.ProviderId }).IsUnique();
    }
}

public sealed class OAuthTokenConfiguration : IEntityTypeConfiguration<OAuthTokenEntity>
{
    public void Configure(EntityTypeBuilder<OAuthTokenEntity> b)
    {
        b.ToTable("oauth_tokens");
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasDefaultValueSql("gen_random_uuid()");
        b.Property(x => x.ProviderKey).HasMaxLength(100).IsRequired();
        b.Property(x => x.Account).HasMaxLength(255).IsRequired();
        b.Property(x => x.AccessTokenCipher).HasColumnType("bytea").IsRequired();
        b.Property(x => x.RefreshTokenCipher).HasColumnType("bytea").IsRequired();
        b.Property(x => x.ScopesJson).HasColumnType("jsonb");
        b.Property(x => x.CreatedAt).HasDefaultValueSql("now()");
        b.HasIndex(x => new { x.UserId, x.ProviderId, x.Account }).IsUnique();
        b.HasIndex(x => x.ExpiresAt);
    }
}
