using System.Security.Claims;
using System.Text.Encodings.Web;
using DonkeyWork.Vault.Proto.V1;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace DonkeyWork.Portal.Api.Auth;

/// <summary>
/// Authenticates a request bearing an access key — <c>X-Api-Key: dwv_…</c> or
/// <c>Authorization: Bearer dwv_…</c> — by asking the vault to resolve it (over the trusted
/// internal hop). On success the principal carries the owner's <c>sub</c>/<c>tenant_id</c> plus a
/// <c>scope</c> claim per granted scope; the scheme name is <see cref="SchemeName"/> so the scope
/// gate can tell API-key callers apart from interactive (JWT) users.
/// </summary>
public sealed class ApiKeyAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    AccessKeys.AccessKeysClient accessKeys)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "ApiKey";
    public const string KeyPrefix = "dwv_";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var secret = ExtractKey();
        if (secret is null)
        {
            return AuthenticateResult.NoResult();
        }

        AuthenticateApiKeyResponse resp;
        try
        {
            resp = await accessKeys.AuthenticateAsync(new AuthenticateApiKeyRequest { Secret = secret });
        }
        catch (Grpc.Core.RpcException ex)
        {
            return AuthenticateResult.Fail(ex.Status.Detail);
        }
        if (!resp.Valid)
        {
            return AuthenticateResult.Fail("Invalid or disabled API key.");
        }

        var claims = new List<Claim>
        {
            new("sub", resp.UserId),
            new(ClaimTypes.NameIdentifier, resp.UserId),
        };
        if (!string.IsNullOrEmpty(resp.TenantId))
        {
            claims.Add(new Claim("tenant_id", resp.TenantId));
        }
        claims.AddRange(resp.Scopes.Select(s => new Claim("scope", s)));

        var identity = new ClaimsIdentity(claims, SchemeName, "sub", roleType: null);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName);
        return AuthenticateResult.Success(ticket);
    }

    private string? ExtractKey()
    {
        var header = Request.Headers["X-Api-Key"].ToString();
        if (!string.IsNullOrEmpty(header) && header.StartsWith(KeyPrefix, StringComparison.Ordinal))
        {
            return header;
        }
        var auth = Request.Headers.Authorization.ToString();
        const string bearer = "Bearer ";
        if (auth.StartsWith(bearer, StringComparison.OrdinalIgnoreCase))
        {
            var token = auth[bearer.Length..].Trim();
            if (token.StartsWith(KeyPrefix, StringComparison.Ordinal))
            {
                return token;
            }
        }
        return null;
    }
}
