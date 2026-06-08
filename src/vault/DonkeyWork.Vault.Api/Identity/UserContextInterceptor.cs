using DonkeyWork.Vault.Core.Services;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace DonkeyWork.Vault.Api.Identity;

/// <summary>
/// Authentication gateway for every gRPC call. Establishes the caller identity (and, for API-key
/// callers, enforces scopes) before publishing it to <see cref="VaultCallerContext"/>. Precedence:
/// <list type="number">
///   <item><c>x-api-key</c> — resolved to an owner + scopes; the method's required scope is enforced.</item>
///   <item><c>x-internal-token</c> — the trusted Portal hop; the asserted <c>x-user-id</c> is trusted.</item>
///   <item>bare <c>x-user-id</c> — legacy/on-prem only, off unless <see cref="VaultAuthOptions.AllowUnauthenticatedUserId"/>.</item>
/// </list>
/// </summary>
public sealed class UserContextInterceptor(IOptions<VaultAuthOptions> options) : Interceptor
{
    private const string Package = "donkeywork.vault.v1";

    // The OAuth callback exchange is anonymous — it derives identity from the state row.
    private static readonly string AnonymousMethod = $"/{Package}.OAuthFlow/Complete";

    // The portal resolves a presented key here before any user identity exists — internal-token only.
    private static readonly string AuthenticateMethod = $"/{Package}.AccessKeys/Authenticate";

    // Required vault scope per method, for API-key callers. "readwrite" implies "read".
    // Unmapped methods fail closed (treated as requiring readwrite).
    private static readonly IReadOnlyDictionary<string, string> MethodScopes = BuildMethodScopes();

    private readonly VaultAuthOptions _options = options.Value;

    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        var method = context.Method;
        if (method == AnonymousMethod)
        {
            return await continuation(request, context);
        }

        var headers = context.RequestHeaders;

        // (2-only) Authenticate is the portal's bootstrap: it must carry the internal token.
        if (method == AuthenticateMethod)
        {
            if (!InternalTokenValid(headers))
            {
                throw Unauthenticated("internal token required.");
            }
            return await continuation(request, context);
        }

        // (1) API key — owner + scopes, enforced against the method.
        var apiKey = headers.GetValue("x-api-key");
        if (!string.IsNullOrEmpty(apiKey))
        {
            var svc = context.GetHttpContext().RequestServices.GetRequiredService<IAccessKeyService>();
            var principal = await svc.AuthenticateAsync(apiKey, context.CancellationToken);
            if (principal is null)
            {
                throw Unauthenticated("invalid or disabled API key.");
            }
            var required = MethodScopes.TryGetValue(method, out var s) ? s : "vault:readwrite";
            if (!HasScope(principal.Scopes, required))
            {
                throw new RpcException(new Status(StatusCode.PermissionDenied, $"API key missing required scope '{required}'."));
            }
            VaultCallerContext.Set(principal.UserId, principal.TenantId);
            return await continuation(request, context);
        }

        // (2) Trusted Portal hop — trust the asserted identity.
        if (InternalTokenValid(headers))
        {
            if (!TryReadUser(headers, out var hopUser, out var hopTenant))
            {
                throw Unauthenticated("missing or invalid x-user-id metadata.");
            }
            VaultCallerContext.Set(hopUser, hopTenant);
            return await continuation(request, context);
        }

        // (3) Legacy bare user-id — on-prem/trusted-network only, off by default.
        if (_options.AllowUnauthenticatedUserId && TryReadUser(headers, out var userId, out var tenantId))
        {
            VaultCallerContext.Set(userId, tenantId);
            return await continuation(request, context);
        }

        throw Unauthenticated("authentication required: present an x-api-key.");
    }

    private bool InternalTokenValid(Metadata headers) =>
        !string.IsNullOrEmpty(_options.InternalToken) &&
        headers.GetValue("x-internal-token") == _options.InternalToken;

    private static bool TryReadUser(Metadata headers, out Guid userId, out Guid tenantId)
    {
        tenantId = Guid.Empty;
        var rawUser = headers.GetValue("x-user-id");
        if (string.IsNullOrEmpty(rawUser) || !Guid.TryParse(rawUser, out userId))
        {
            userId = Guid.Empty;
            return false;
        }
        Guid.TryParse(headers.GetValue("x-tenant-id"), out tenantId);
        return true;
    }

    private static bool HasScope(IReadOnlyList<string> granted, string required)
    {
        if (granted.Contains(required))
        {
            return true;
        }
        // readwrite implies read
        if (required.EndsWith(":read", StringComparison.Ordinal))
        {
            var readwrite = string.Concat(required.AsSpan(0, required.Length - ":read".Length), ":readwrite");
            return granted.Contains(readwrite);
        }
        return false;
    }

    private static RpcException Unauthenticated(string detail) =>
        new(new Status(StatusCode.Unauthenticated, detail));

    private static Dictionary<string, string> BuildMethodScopes()
    {
        const string r = "vault:read";
        const string w = "vault:readwrite";
        return new Dictionary<string, string>
        {
            [$"/{Package}.CredentialStore/GetApiKey"] = r,
            [$"/{Package}.CredentialStore/DescribeCredential"] = r,
            [$"/{Package}.CredentialStore/GetOAuthAccessToken"] = r,
            [$"/{Package}.OAuthTokens/List"] = r,
            [$"/{Package}.ApiKeys/List"] = r,
            [$"/{Package}.ApiKeys/Create"] = w,
            [$"/{Package}.ApiKeys/Delete"] = w,
            [$"/{Package}.ApiKeyCatalog/ListProviders"] = r,
            [$"/{Package}.ApiKeyCatalog/GetProvider"] = r,
            [$"/{Package}.Manifests/ListApiKey"] = r,
            [$"/{Package}.Manifests/UpsertApiKey"] = w,
            [$"/{Package}.Manifests/ListOAuth"] = r,
            [$"/{Package}.Manifests/UpsertOAuth"] = w,
            [$"/{Package}.Manifests/Delete"] = w,
            [$"/{Package}.Manifests/DiscoverOidc"] = r,
            [$"/{Package}.OAuthProviderConfigs/List"] = r,
            [$"/{Package}.OAuthProviderConfigs/Upsert"] = w,
            [$"/{Package}.OAuthProviderConfigs/Delete"] = w,
            [$"/{Package}.OAuthFlow/Begin"] = w,
            [$"/{Package}.AccessKeys/List"] = r,
            [$"/{Package}.AccessKeys/Create"] = w,
            [$"/{Package}.AccessKeys/SetEnabled"] = w,
            [$"/{Package}.AccessKeys/Delete"] = w,
        };
    }
}
