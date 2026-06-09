using DonkeyWork.Vault.Contracts.Audit;
using DonkeyWork.Vault.Core.Audit;
using DonkeyWork.Vault.Core.Crypto;
using DonkeyWork.Vault.Core.Manifests;
using DonkeyWork.Vault.Core.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace DonkeyWork.Vault.Core;

public static class DependencyInjection
{
    public static IServiceCollection AddVaultCore(this IServiceCollection services)
    {
        services.AddOptions<VaultCryptoOptions>()
            .BindConfiguration(VaultCryptoOptions.SectionName)
            .ValidateOnStart();

        AddVaultAudit(services);

        services.AddSingleton<IKekProvider, LocalKekProvider>();
        services.AddSingleton<IEnvelopeCipher, EnvelopeCipherService>();
        services.AddSingleton<OAuthManifestLoader>();

        services.AddHttpClient();
        services.AddSingleton<OAuthDiscoveryService>();
        services.AddScoped<ManifestResolver>();
        services.AddScoped<IApiKeyService, ApiKeyService>();
        services.AddScoped<IAccessKeyService, AccessKeyService>();
        services.AddScoped<IOAuthTokenService, OAuthTokenService>();
        services.AddScoped<IOAuthProviderConfigService, OAuthProviderConfigService>();
        services.AddScoped<IOAuthFlowService, OAuthFlowService>();

        return services;
    }

    /// <summary>
    /// Registers the audit subsystem: the AsyncLocal request-context accessor, the singleton
    /// bounded-channel sink, and the background writer + retention job. All fire-and-forget — the
    /// sink never blocks or throws on the credential path.
    /// </summary>
    private static void AddVaultAudit(IServiceCollection services)
    {
        services.AddOptions<AuditOptions>()
            .BindConfiguration(AuditOptions.SectionName);

        services.AddSingleton<IAuditContextAccessor, AuditContextAccessor>();

        // The sink is a singleton exposed both as IAuditLog (enqueue) and concretely (the writer
        // drains its reader and signals completion on shutdown).
        services.AddSingleton<AuditLog>();
        services.AddSingleton<IAuditLog>(sp => sp.GetRequiredService<AuditLog>());

        services.AddHostedService<AuditLogWriter>();
        services.AddHostedService<AuditRetentionJob>();

        // Per-request convenience wrapper used by the domain services to emit events.
        services.AddScoped<AuditEmitter>();

        // Read side of the trail (admin/cross-user; gated by the vault:audit scope at the transport).
        services.AddScoped<IAuditQueryService, AuditQueryService>();
    }
}
