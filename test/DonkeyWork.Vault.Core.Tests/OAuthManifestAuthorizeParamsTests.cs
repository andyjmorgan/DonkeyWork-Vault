using DonkeyWork.Vault.Core.Manifests;

namespace DonkeyWork.Vault.Core.Tests;

public class OAuthManifestAuthorizeParamsTests
{
    // Google's offline/consent params must come from google.yaml, not a hardcode in OAuthFlowService.
    [Fact]
    public void Google_Template_DeclaresOfflineAuthorizeParams()
    {
        var google = new OAuthManifestLoader().Get("google");
        Assert.NotNull(google);
        Assert.Equal("offline", google!.AuthorizeParams.GetValueOrDefault("access_type"));
        Assert.Equal("consent", google.AuthorizeParams.GetValueOrDefault("prompt"));
    }
}
