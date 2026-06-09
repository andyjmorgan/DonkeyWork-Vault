using System.Security.Claims;
using DonkeyWork.Vault.Api.Identity;
using DonkeyWork.Vault.Contracts.Audit;
using DonkeyWork.Vault.Core.Services;

namespace DonkeyWork.Vault.Api.Http.Audit;

/// <summary>
/// Establishes the per-request ambient state for the in-flight HTTP request, once authentication has
/// run: the caller identity (<see cref="VaultCallerContext"/>, which feeds the DbContext per-user query
/// filter) and the audit metadata (<see cref="IAuditContextAccessor"/> — resolved source IP, redacted
/// headers, and the access-key reference). It runs <b>after</b> <c>UseAuthentication</c>/<c>UseAuthorization</c>
/// and <b>before</b> the endpoints, so both ambient values flow down (AsyncLocal) into the domain
/// services. This is the HTTP replacement for the gRPC <c>UserContextInterceptor</c>'s context-publishing.
/// </summary>
public sealed class AuditContextMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext ctx, IAuditContextAccessor auditContext)
    {
        // Only the API surface needs the ambient context published; static SPA assets pass straight
        // through (they touch no credential and emit no audit events).
        if (!ctx.Request.Path.StartsWithSegments("/api"))
        {
            await next(ctx);
            return;
        }

        var principal = ctx.Items.TryGetValue(HttpAuditContext.PrincipalItemKey, out var p)
            ? p as AccessKeyPrincipal
            : null;

        // Caller identity, for authenticated requests (JWT users or API-key owners). Anonymous
        // endpoints (OAuth callback, public config, health) leave it empty — those derive identity
        // elsewhere (the OAuth callback from its state row).
        if (ctx.User.Identity?.IsAuthenticated == true)
        {
            var userId = ParseGuid(ctx.User.FindFirst("sub")?.Value ?? ctx.User.FindFirst(ClaimTypes.NameIdentifier)?.Value);
            var tenantId = ParseGuid(ctx.User.FindFirst("tenant_id")?.Value);
            VaultCallerContext.Set(userId, tenantId);
        }

        auditContext.Set(new AuditRequestInfo(
            SourceIp: HttpAuditContext.SourceIp(ctx),
            Headers: HttpAuditContext.RedactedHeaders(ctx),
            AccessKeyId: principal?.Id,
            AccessKeyPrefix: principal?.KeyPrefix,
            AccessKeyName: principal?.Name,
            Transport: HttpAuditContext.Transport,
            Method: HttpAuditContext.Method(ctx)));

        await next(ctx);
    }

    private static Guid ParseGuid(string? value) => Guid.TryParse(value, out var g) ? g : Guid.Empty;
}
