using System.Security.Claims;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace DonkeyWork.Portal.Api.Vault;

/// <summary>
/// gRPC client interceptor that forwards the authenticated caller's identity to the vault
/// as x-user-id (Keycloak `sub`) and x-tenant-id metadata.
/// </summary>
public sealed class UserIdInterceptor(IHttpContextAccessor accessor) : Interceptor
{
    public override AsyncUnaryCall<TResponse> AsyncUnaryCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncUnaryCallContinuation<TRequest, TResponse> continuation)
    {
        var user = accessor.HttpContext?.User;
        var sub = user?.FindFirst("sub")?.Value ?? user?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        var headers = context.Options.Headers ?? new Metadata();
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
