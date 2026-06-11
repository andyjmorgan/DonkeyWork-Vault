using DonkeyWork.Vault.Api.Http.Auth;

namespace DonkeyWork.Vault.Integration.Tests;

public sealed class OidcOptionsTests
{
    [Fact]
    public void EffectiveWebClientId_PreservesLegacyClientIdFallback()
    {
        var options = new OidcOptions
        {
            Audience = "donkeywork-vault-web",
            ClientId = "legacy-web",
            Scopes = "openid profile email",
        };

        Assert.Equal("legacy-web", options.EffectiveWebClientId);
        Assert.Equal("openid profile email", options.EffectiveWebScopes);
    }

    [Fact]
    public void EffectiveCliDefaults_AreDeviceClientAndOfflineScopes()
    {
        var options = new OidcOptions();

        Assert.Equal("donkeywork-vault-cli", options.EffectiveCliClientId);
        Assert.Equal("openid profile email offline_access", options.EffectiveCliScopes);
    }
}
