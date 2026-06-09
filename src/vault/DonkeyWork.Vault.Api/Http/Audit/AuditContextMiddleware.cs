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

            // An authenticated principal whose subject is not a GUID must NOT fall through to the
            // empty-Guid bucket — the DbContext per-user query filter scopes to CurrentUserId, so
            // every such caller would share one anonymous bucket. Reject instead of silently scoping.
            if (userId == Guid.Empty)
            {
                ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await ctx.Response.WriteAsJsonAsync(new ErrorResponse("authenticated subject is missing or not a valid identifier."));
                return;
            }

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

        try
        {
            await next(ctx);
        }
        finally
        {
            // Reset the ambient AsyncLocals so no caller/audit metadata lingers on this execution
            // flow after the response (defence against fire-and-forget work capturing the context).
            VaultCallerContext.Set(Guid.Empty, Guid.Empty);
            auditContext.Set(AuditRequestInfo.Empty);
        }
    }

    private static Guid ParseGuid(string? value) => Guid.TryParse(value, out var g) ? g : Guid.Empty;
}
