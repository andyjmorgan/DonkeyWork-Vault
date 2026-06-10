using DonkeyWork.Vault.Core.Manifests;
using DonkeyWork.Vault.Core.Services;

namespace DonkeyWork.Vault.Core.Tests;

public class OAuthScopeAllowlistTests
{
    private static OAuthManifest Manifest(string[] catalog, string[] defaults) => new()
    {
        Scopes = catalog.Select(v => new OAuthScopeDef { Value = v }).ToList(),
        DefaultScopes = defaults.ToList(),
    };

    [Fact]
    public void Drops_Scopes_Not_In_Catalog_Or_Defaults_PreservingOrder()
    {
        var m = Manifest(["files.metadata.read", "files.content.write"], ["openid"]);
        var (kept, dropped) = OAuthFlowService.FilterScopesToCatalog(
            m, ["openid", "offline", "files.content.write", "bogus"]);

        Assert.Equal(["openid", "files.content.write"], kept);   // order preserved, allowed kept
        Assert.Equal(["offline", "bogus"], dropped);              // the stray "offline" is dropped
    }

    [Fact]
    public void Defaults_Count_As_Allowed_Even_If_Not_In_Catalog()
    {
        var m = Manifest(["files.metadata.read"], ["openid", "email"]);
        var (kept, dropped) = OAuthFlowService.FilterScopesToCatalog(m, ["openid", "email"]);
        Assert.Equal(["openid", "email"], kept);
        Assert.Empty(dropped);
    }

    [Fact]
    public void Empty_Catalog_And_Defaults_PassesThroughUnfiltered()
    {
        var m = Manifest([], []);
        var (kept, dropped) = OAuthFlowService.FilterScopesToCatalog(m, ["anything", "goes"]);
        Assert.Equal(["anything", "goes"], kept);
        Assert.Empty(dropped);
    }
}
