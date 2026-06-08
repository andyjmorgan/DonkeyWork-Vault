using System.Security.Claims;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Microsoft.Extensions.Configuration;

namespace DonkeyWork.Portal.Api.Vault;

/// <summary>
/// gRPC client interceptor that authenticates the Portal's hop to the vault with a shared
/// internal service token (x-internal-token) and forwards the caller's asserted identity as
/// x-user-id (Keycloak `sub`) and x-tenant-id metadata.
/// </summary>
public sealed class UserIdInterceptor(IHttpContextAccessor accessor, IConfiguration config) : Interceptor
{
    private readonly string? _internalToken = config["Vault:InternalToken"];

    public override AsyncUnaryCall<TResponse> AsyncUnaryCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncUnaryCallContinuation<TRequest, TResponse> continuation)
    {
        var user = accessor.HttpContext?.User;
        var sub = user?.FindFirst("sub")?.Value ?? user?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        var headers = context.Options.Headers ?? new Metadata();
        if (!string.IsNullOrEmpty(_internalToken))
        {
            headers.Add("x-internal-token", _internalToken);
        }
        if (!string.IsNullOrEmpty(sub))
        {
            headers.Add("x-user-id", sub);
        }
        var tenant = user?.FindFirst("tenant_id")?.Value;
        if (!string.IsNullOrEmpty(tenant))
        {
            headers.Add("x-tenant-id", tenant);
        }

        var newContext = new ClientInterceptorContext<TRequest, TResponse>(
            context.Method, context.Host, context.Options.WithHeaders(headers));
        return continuation(request, newContext);
    }
}
