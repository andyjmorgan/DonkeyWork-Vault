using DonkeyWork.Vault.Core.Crypto;
using DonkeyWork.Vault.Core.Manifests;
using DonkeyWork.Vault.Core.Services;
using Microsoft.Extensions.DependencyInjection;

namespace DonkeyWork.Vault.Core;

public static class DependencyInjection
{
    public static IServiceCollection AddVaultCore(this IServiceCollection services)
    {
        services.AddOptions<VaultCryptoOptions>()
            .BindConfiguration(VaultCryptoOptions.SectionName)
            .ValidateOnStart();

        services.AddSingleton<IKekProvider, LocalKekProvider>();
        services.AddSingleton<IEnvelopeCipher, EnvelopeCipherService>();
        services.AddSingleton<ApiKeyManifestLoader>();
        services.AddSingleton<OAuthManifestLoader>();

        services.AddHttpClient();
        services.AddScoped<IApiKeyService, ApiKeyService>();
        services.AddScoped<IOAuthTokenService, OAuthTokenService>();

        return services;
    }
}
