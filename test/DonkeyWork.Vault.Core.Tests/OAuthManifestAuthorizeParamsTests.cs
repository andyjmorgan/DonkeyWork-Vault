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

    // Dropbox only issues a refresh_token when token_access_type=offline is on the authorize URL.
    [Fact]
    public void Dropbox_Template_DeclaresOfflineAuthorizeParam()
    {
        var dropbox = new OAuthManifestLoader().Get("dropbox");
        Assert.NotNull(dropbox);
        Assert.Equal("offline", dropbox!.AuthorizeParams.GetValueOrDefault("token_access_type"));
        Assert.NotEqual(System.Guid.Empty, dropbox.Id);
    }
}
