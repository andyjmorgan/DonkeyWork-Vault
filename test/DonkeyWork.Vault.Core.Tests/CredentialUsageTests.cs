using System.Text;
using DonkeyWork.Vault.Core.Services;

namespace DonkeyWork.Vault.Core.Tests;

public class CredentialUsageTests
{
    [Fact]
    public void Scheme_IsBasic_WhenUsernamePresent()
    {
        Assert.Equal(CredentialUsage.Basic, CredentialUsage.Scheme("admin"));
        Assert.Equal(CredentialUsage.Header, CredentialUsage.Scheme(null));
        Assert.Equal(CredentialUsage.Header, CredentialUsage.Scheme(""));
    }

    [Fact]
    public void HeaderName_DefaultsToAuthorization_WhenMissing()
    {
        Assert.Equal("Authorization", CredentialUsage.HeaderName(null));
        Assert.Equal("Authorization", CredentialUsage.HeaderName(""));
        Assert.Equal("x-api-key", CredentialUsage.HeaderName("x-api-key"));
    }

    [Fact]
    public void AssembleHeader_BearerToken_UsesPrefixAndSecret()
    {
        var (name, value) = CredentialUsage.AssembleHeader("Authorization", "Bearer ", null, "glsa_123");
        Assert.Equal("Authorization", name);
        Assert.Equal("Bearer glsa_123", value);
    }

    [Fact]
    public void AssembleHeader_EmptyHeader_StillWellFormed()
    {
        // Regression: a token credential with no stored header must not yield ": secret".
        var (name, value) = CredentialUsage.AssembleHeader(null, null, null, "secret");
        Assert.Equal("Authorization", name);
        Assert.Equal("secret", value);
    }

    [Fact]
    public void AssembleHeader_Basic_EncodesUserAndPassword()
    {
        var (name, value) = CredentialUsage.AssembleHeader(null, null, "admin", "hunter2");
        Assert.Equal("Authorization", name);
        Assert.Equal("Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("admin:hunter2")), value);
    }
}
