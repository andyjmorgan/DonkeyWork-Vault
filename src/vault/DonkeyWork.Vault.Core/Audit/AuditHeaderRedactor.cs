namespace DonkeyWork.Vault.Core.Audit;

/// <summary>
/// Centralised, deny-by-default header redaction for the audit trail. Request headers carry
/// bearer secrets, so only an explicit allowlist is stored verbatim; everything else keeps its
/// key but has its value replaced with <see cref="Redacted"/> (so an admin can see a header was
/// present without leaking it). Always case-insensitive; redaction is applied here, before the
/// value ever reaches the entity. This is the single place the allow/deny lists live so they are
/// auditable and unit-tested, and both the gRPC interceptor and any future HTTP middleware use it.
/// </summary>
public static class AuditHeaderRedactor
{
    public const string Redacted = "***";

    /// <summary>Stored verbatim. Known-safe, non-secret headers only.</summary>
    private static readonly HashSet<string> Allowlist = new(StringComparer.OrdinalIgnoreCase)
    {
        "user-agent",
        "content-type",
        "accept",
        "x-request-id",
        "traceparent",
        "x-forwarded-for",
        "x-real-ip",
        "x-forwarded-proto",
        "host",
    };

    /// <summary>Always redacted, even though they might otherwise look innocuous.</summary>
    private static readonly HashSet<string> DenyExact = new(StringComparer.OrdinalIgnoreCase)
    {
        "authorization",
        "x-api-key",
        "x-internal-token",
        "cookie",
        "set-cookie",
        "proxy-authorization",
    };

    /// <summary>
    /// Redact a single header value by name. Returns the verbatim value for allowlisted headers,
    /// otherwise <see cref="Redacted"/>. Deny patterns (<c>*token*</c> / <c>*secret*</c> /
    /// <c>*password*</c> / <c>*-key</c>) and the explicit deny list always win over the allowlist.
    /// </summary>
    public static string Redact(string name, string value)
    {
        if (string.IsNullOrEmpty(name))
        {
            return Redacted;
        }

        // Deny always wins, even if a header somehow appears on both lists.
        if (IsDenied(name))
        {
            return Redacted;
        }

        return Allowlist.Contains(name) ? value : Redacted;
    }

    /// <summary>
    /// Project a header collection into the redacted dictionary stored on the audit event.
    /// Keys are lower-cased for stable, case-insensitive storage; duplicate keys keep the first.
    /// </summary>
    public static IReadOnlyDictionary<string, string> Redact(IEnumerable<KeyValuePair<string, string>> headers)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, value) in headers)
        {
            if (string.IsNullOrEmpty(name))
            {
                continue;
            }
            var key = name.ToLowerInvariant();
            if (result.ContainsKey(key))
            {
                continue;
            }
            result[key] = Redact(name, value);
        }
        return result;
    }

    /// <summary>True if the header name is denied by exact match or a secret-bearing pattern.</summary>
    public static bool IsDenied(string name)
    {
        if (DenyExact.Contains(name))
        {
            return true;
        }

        var lower = name.ToLowerInvariant();
        return lower.Contains("token")
            || lower.Contains("secret")
            || lower.Contains("password")
            || lower.EndsWith("-key", StringComparison.Ordinal);
    }
}
