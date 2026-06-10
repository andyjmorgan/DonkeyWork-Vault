using DonkeyWork.Vault.Core.Manifests;

namespace DonkeyWork.Vault.Core.Tests;

public class OAuthDiscoveryKeyTests
{
    [Theory]
    [InlineData("www.dropbox.com", "dropbox")]      // the reported bug: must not be "www"
    [InlineData("dropbox.com", "dropbox")]
    [InlineData("accounts.google.com", "google")]
    [InlineData("login.microsoftonline.com", "microsoftonline")]
    [InlineData("WWW.Dropbox.COM", "dropbox")]       // case-insensitive + www stripped
    [InlineData("localhost", "localhost")]            // single label returned as-is
    public void KeyFromHost_UsesRegistrableLabel(string host, string expected) =>
        Assert.Equal(expected, OAuthDiscoveryService.KeyFromHost(host));

    [Theory]
    [InlineData("www.dropbox.com", "dropbox.com")]
    [InlineData("accounts.google.com", "accounts.google.com")]
    public void NormalizeHost_DropsLeadingWww(string host, string expected) =>
        Assert.Equal(expected, OAuthDiscoveryService.NormalizeHost(host));
}
