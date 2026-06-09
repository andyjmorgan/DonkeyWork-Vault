using System.Security.Claims;
using System.Text.Encodings.Web;
using DonkeyWork.Vault.Api.Http.Audit;
using DonkeyWork.Vault.Contracts.Audit;
using DonkeyWork.Vault.Core.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace DonkeyWork.Vault.Api.Http.Auth;

/// <summary>
/// Authenticates a request bearing an access key — <c>X-Api-Key: dwv_…</c> or
/// <c>Authorization: Bearer dwv_…</c> — by resolving it directly against <see cref="IAccessKeyService"/>
/// (no gRPC, no internal-token hop: the vault is the authority). On success the principal carries the
/// owner's <c>sub</c>/<c>tenant_id</c> plus a <c>scope</c> claim per granted scope, and the resolved
/// <see cref="AccessKeyPrincipal"/> is stashed in <c>HttpContext.Items</c> so the audit middleware can
/// reference the key (id/prefix/name — never the secret) on every subsequent event. Auth outcomes are
/// themselves audited here, where IP and redacted headers are resolved from the connection.
/// </summary>
public sealed class VaultApiKeyAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder)
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

        var accessKeys = Context.RequestServices.GetRequiredService<IAccessKeyService>();
        AccessKeyPrincipal? principal;
        try
        {
            principal = await accessKeys.AuthenticateAsync(secret, Context.RequestAborted);
        }
        catch (Exception ex)
        {
            EmitAuthFailed("api key resolution failed.");
            return AuthenticateResult.Fail(ex.Message);
        }

        if (principal is null)
        {
            EmitAuthFailed("invalid or disabled API key.");
            return AuthenticateResult.Fail("Invalid or disabled API key.");
        }

        // Stash for the audit middleware (key reference for every later event) and the scope gate.
        Context.Items[HttpAuditContext.PrincipalItemKey] = principal;

        var claims = new List<Claim>
        {
            new("sub", principal.UserId.ToString()),
            new(ClaimTypes.NameIdentifier, principal.UserId.ToString()),
        };
        if (principal.TenantId != Guid.Empty)
        {
            claims.Add(new Claim("tenant_id", principal.TenantId.ToString()));
        }
        claims.AddRange(principal.Scopes.Select(s => new Claim("scope", s)));

        EmitAuthSucceeded(principal);

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

    private void EmitAuthSucceeded(AccessKeyPrincipal principal)
    {
        var auditLog = Context.RequestServices.GetRequiredService<IAuditLog>();
        auditLog.Enqueue(new AuditEvent(
            AuditEventType.AuthSucceeded, AuditOutcome.Success,
            principal.UserId, principal.TenantId,
            principal.Id, principal.KeyPrefix, principal.Name,
            HttpAuditContext.SourceIp(Context), HttpAuditContext.RedactedHeaders(Context),
            TargetKind: "access_key", TargetProvider: null, TargetAccount: null, TargetName: principal.Name,
            HttpAuditContext.Transport, HttpAuditContext.Method(Context), Detail: null, CreatedAt: DateTimeOffset.UtcNow));
    }

    private void EmitAuthFailed(string reason)
    {
        var auditLog = Context.RequestServices.GetRequiredService<IAuditLog>();
        auditLog.Enqueue(new AuditEvent(
            AuditEventType.AuthFailed, AuditOutcome.Failure,
            UserId: Guid.Empty, TenantId: Guid.Empty,
            AccessKeyId: null, AccessKeyPrefix: null, AccessKeyName: null,
            HttpAuditContext.SourceIp(Context), HttpAuditContext.RedactedHeaders(Context),
            TargetKind: null, TargetProvider: null, TargetAccount: null, TargetName: null,
            HttpAuditContext.Transport, HttpAuditContext.Method(Context), Detail: reason, CreatedAt: DateTimeOffset.UtcNow));
    }
}
