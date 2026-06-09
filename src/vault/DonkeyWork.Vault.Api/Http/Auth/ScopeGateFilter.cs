using DonkeyWork.Vault.Api.Http.Audit;
using DonkeyWork.Vault.Contracts.Audit;

namespace DonkeyWork.Vault.Api.Http.Auth;

/// <summary>
/// Scope gate for API-key callers. GET/HEAD/OPTIONS need <c>vault:read</c>, mutations need
/// <c>vault:readwrite</c> (which implies read); endpoints can pin a <see cref="_fixedScope"/> such as
/// <c>vault:audit</c>. Interactive JWT users are not scope-limited. A denial is audited as
/// <see cref="AuditEventType.AuthFailed"/> and returns 403. This is the HTTP equivalent of the gRPC
/// interceptor's per-method scope enforcement.
/// </summary>
public sealed class ScopeGateFilter(string? fixedScope = null) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        var user = http.User;
        if (user.Identity?.AuthenticationType == VaultApiKeyAuthenticationHandler.SchemeName)
        {
            var method = http.Request.Method;
            var required = fixedScope
                ?? (HttpMethods.IsGet(method) || HttpMethods.IsHead(method) || HttpMethods.IsOptions(method)
                    ? "vault:read"
                    : "vault:readwrite");

            var scopes = user.FindAll("scope").Select(c => c.Value).ToHashSet(StringComparer.Ordinal);
            if (!HasScope(scopes, required))
            {
                EmitScopeDenied(http, required);
                return Results.Json(new ErrorResponse($"API key missing required scope '{required}'."),
                    statusCode: StatusCodes.Status403Forbidden);
            }
        }

        return await next(context);
    }

    private static bool HasScope(HashSet<string> granted, string required)
    {
        if (granted.Contains(required))
        {
            return true;
        }
        // readwrite implies read (audit is standalone — not implied by readwrite).
        if (required.EndsWith(":read", StringComparison.Ordinal))
        {
            var readwrite = string.Concat(required.AsSpan(0, required.Length - ":read".Length), ":readwrite");
            return granted.Contains(readwrite);
        }
        return false;
    }

    private static void EmitScopeDenied(HttpContext http, string required)
    {
        var auditLog = http.RequestServices.GetRequiredService<IAuditLog>();
        var info = http.RequestServices.GetRequiredService<IAuditContextAccessor>().Current;
        var userId = Guid.TryParse(http.User.FindFirst("sub")?.Value, out var u) ? u : Guid.Empty;
        var tenantId = Guid.TryParse(http.User.FindFirst("tenant_id")?.Value, out var t) ? t : Guid.Empty;
        auditLog.Enqueue(new AuditEvent(
            AuditEventType.AuthFailed, AuditOutcome.Failure,
            userId, tenantId,
            info.AccessKeyId, info.AccessKeyPrefix, info.AccessKeyName,
            info.SourceIp, info.Headers,
            TargetKind: null, TargetProvider: null, TargetAccount: null, TargetName: null,
            info.Transport, info.Method, Detail: $"missing scope '{required}'.", CreatedAt: DateTimeOffset.UtcNow));
    }
}
