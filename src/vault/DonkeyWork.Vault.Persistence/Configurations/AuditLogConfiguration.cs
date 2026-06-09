using System.Text.Json;
using DonkeyWork.Vault.Persistence.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace DonkeyWork.Vault.Persistence.Configurations;

public sealed class AuditLogConfiguration : IEntityTypeConfiguration<AuditLogEntity>
{
    public void Configure(EntityTypeBuilder<AuditLogEntity> b)
    {
        b.ToTable("audit_log");
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasDefaultValueSql("gen_random_uuid()");

        b.Property(x => x.EventType).IsRequired();
        b.Property(x => x.Outcome).IsRequired();
        b.Property(x => x.UserId).IsRequired();
        b.Property(x => x.TenantId).IsRequired();

        b.Property(x => x.AccessKeyPrefix).HasMaxLength(32);
        b.Property(x => x.AccessKeyName).HasMaxLength(255);

        // Resolved real client IP. Postgres inet; nullable when unknown.
        b.Property(x => x.SourceIp).HasColumnType("inet");

        // Redacted headers, persisted as jsonb. A value converter (string<->dict) plus a value
        // comparer so EF tracks the dictionary correctly (it is never updated, but the comparer
        // keeps the model valid).
        var headersConverter = new Microsoft.EntityFrameworkCore.Storage.ValueConversion.ValueConverter<IReadOnlyDictionary<string, string>, string>(
            v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
            v => JsonSerializer.Deserialize<Dictionary<string, string>>(v, (JsonSerializerOptions?)null)
                 ?? new Dictionary<string, string>());

        var headersComparer = new ValueComparer<IReadOnlyDictionary<string, string>>(
            (a, c) => JsonSerializer.Serialize(a, (JsonSerializerOptions?)null) == JsonSerializer.Serialize(c, (JsonSerializerOptions?)null),
            v => v == null ? 0 : JsonSerializer.Serialize(v, (JsonSerializerOptions?)null).GetHashCode(),
            v => v);

        b.Property(x => x.Headers)
            .HasColumnType("jsonb")
            .HasConversion(headersConverter)
            .Metadata.SetValueComparer(headersComparer);

        b.Property(x => x.TargetKind).HasMaxLength(64);
        b.Property(x => x.TargetProvider).HasMaxLength(255);
        b.Property(x => x.TargetAccount).HasMaxLength(320);
        b.Property(x => x.TargetName).HasMaxLength(255);

        b.Property(x => x.Transport).HasMaxLength(16).IsRequired();
        b.Property(x => x.Method).HasMaxLength(255);
        b.Property(x => x.Detail).HasMaxLength(1024);

        b.Property(x => x.CreatedAt).HasDefaultValueSql("now()");

        // Access patterns: primary admin filter, "all of one event type", "what did this key do",
        // retention sweep / time-range export, and tenant/user consistency with existing tables.
        b.HasIndex(x => new { x.UserId, x.CreatedAt }).IsDescending(false, true);
        b.HasIndex(x => new { x.EventType, x.CreatedAt }).IsDescending(false, true);
        b.HasIndex(x => new { x.AccessKeyId, x.CreatedAt }).IsDescending(false, true);
        b.HasIndex(x => x.CreatedAt);
        b.HasIndex(x => new { x.TenantId, x.UserId });
    }
}
