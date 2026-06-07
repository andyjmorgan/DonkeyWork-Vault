using DonkeyWork.Vault.Persistence.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace DonkeyWork.Vault.Persistence;

public static class DependencyInjection
{
    public static IServiceCollection AddVaultPersistence(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<VaultPersistenceOptions>()
            .BindConfiguration(VaultPersistenceOptions.SectionName)
            .ValidateOnStart();

        var connectionString = configuration.GetSection(VaultPersistenceOptions.SectionName)["ConnectionString"]
            ?? configuration.GetConnectionString("Vault")
            ?? throw new InvalidOperationException("Vault:Persistence:ConnectionString is not configured.");

        services.AddDbContext<VaultDbContext>(options =>
            options.UseNpgsql(connectionString, npg =>
                npg.MigrationsHistoryTable("__ef_migrations_history", "vault")));

        services.AddDataProtection()
            .PersistKeysToDbContext<VaultDbContext>();

        services.AddScoped<IMigrationService, MigrationService>();

        return services;
    }
}
