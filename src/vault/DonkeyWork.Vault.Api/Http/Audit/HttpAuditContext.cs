using DonkeyWork.Vault.Core.Audit;

namespace DonkeyWork.Vault.Api.Http.Audit;

/// <summary>
/// Resolves the per-request audit primitives — the real client IP and the deny-by-default redacted
/// request headers — from an <see cref="HttpContext"/>. Shared by the API-key authentication handler
/// (which emits its own auth-outcome events) and the <see cref="AuditContextMiddleware"/> (which
/// publishes the ambient <c>IAuditContextAccessor</c> for the domain services). The IP comes from the
/// connection's <c>RemoteIpAddress</c>, which <c>UseForwardedHeaders</c> has already corrected to the
/// real client behind the trusted proxy.
/// </summary>
public static class HttpAuditContext
{
    public const string Transport = "http";

    /// <summary>HttpContext.Items key under which the resolved API-key principal is stashed by the handler.</summary>
    public const string PrincipalItemKey = "vault.accessKeyPrincipal";

    public static string? SourceIp(HttpContext ctx) => ctx.Connection.RemoteIpAddress?.ToString();

    public static IReadOnlyDictionary<string, string> RedactedHeaders(HttpContext ctx) =>
        AuditHeaderRedactor.Redact(
            ctx.Request.Headers.Select(h => new KeyValuePair<string, string>(h.Key, h.Value.ToString())));

    /// <summary>The audited method label, e.g. <c>GET /api/v1/api-keys</c>.</summary>
    public static string Method(HttpContext ctx) => $"{ctx.Request.Method} {ctx.Request.Path}";
}
