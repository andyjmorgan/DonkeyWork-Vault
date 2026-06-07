using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace DonkeyWork.Vault.Persistence.Design;

/// <summary>
/// Design-time factory so `dotnet ef migrations add` works without the full host.
/// The connection string is only used to pick the Npgsql provider; migrations are
/// authored offline. Override via the VAULT_DB env var to point at a real database.
/// </summary>
public sealed class VaultDbContextFactory : IDesignTimeDbContextFactory<VaultDbContext>
{
    public VaultDbContext CreateDbContext(string[] args)
    {
        var cs = Environment.GetEnvironmentVariable("VAULT_DB")
            ?? "Host=localhost;Port=5432;Database=donkeywork_vault;Username=postgres;Password=postgres";

        var options = new DbContextOptionsBuilder<VaultDbContext>()
            .UseNpgsql(cs, npg => npg.MigrationsHistoryTable("__ef_migrations_history", "vault"))
            .Options;

        return new VaultDbContext(options, caller: null);
    }
}
