using System.Security.Claims;
using DonkeyWork.Vault.Api.Http.Auth;

namespace DonkeyWork.Vault.Integration.Tests;

public sealed class OidcVaultScopeMapperTests
{
    [Fact]
    public void CliClient_GetsReadWriteWithoutAudit()
    {
        var principal = Principal(new Claim("azp", "donkeywork-vault-cli"), new Claim("aud", "donkeywork-vault-web"));

        var scopes = OidcVaultScopeMapper.ScopesFor(principal, "donkeywork-vault-web", "donkeywork-vault-cli");

        Assert.Contains("vault:read", scopes);
        Assert.Contains("vault:readwrite", scopes);
        Assert.DoesNotContain("vault:audit", scopes);
    }

    [Fact]
    public void CliClient_WithoutVaultAudience_GetsNoVaultScopes()
    {
        var principal = Principal(new Claim("azp", "donkeywork-vault-cli"), new Claim("aud", "account"));

        Assert.Empty(OidcVaultScopeMapper.ScopesFor(principal, "donkeywork-vault-web", "donkeywork-vault-cli"));
    }

    [Fact]
    public void WebClient_GetsAudit()
    {
        var principal = Principal(new Claim("azp", "donkeywork-vault-web"));

        var scopes = OidcVaultScopeMapper.ScopesFor(principal, "donkeywork-vault-web", "donkeywork-vault-cli");

        Assert.Contains("vault:audit", scopes);
    }

    [Fact]
    public void UnknownClient_GetsNoVaultScopes()
    {
        var principal = Principal(new Claim("azp", "other-client"));

        Assert.Empty(OidcVaultScopeMapper.ScopesFor(principal, "donkeywork-vault-web", "donkeywork-vault-cli"));
    }

    private static ClaimsPrincipal Principal(params Claim[] claims) =>
        new(new ClaimsIdentity(claims, "Bearer"));
}
