using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace DonkeyWork.Vault.Persistence.Services;

public interface IMigrationService
{
    Task MigrateAsync(CancellationToken cancellationToken = default);
}

public sealed class MigrationService(VaultDbContext db, ILogger<MigrationService> logger) : IMigrationService
{
    public async Task MigrateAsync(CancellationToken cancellationToken = default)
    {
        logger.LogInformation("Applying vault database migrations...");
        await db.Database.MigrateAsync(cancellationToken);
        logger.LogInformation("Vault database migrations applied.");
    }
}
