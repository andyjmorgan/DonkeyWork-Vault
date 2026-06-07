using Grpc.Core;
using Grpc.Core.Interceptors;

namespace DonkeyWork.Vault.Api.Identity;

/// <summary>
/// Reads x-user-id (required) and x-tenant-id (optional) from gRPC metadata and publishes
/// them to <see cref="VaultCallerContext"/>. Rejects calls without a valid user id.
/// </summary>
public sealed class UserContextInterceptor : Interceptor
{
    // The OAuth callback exchange is anonymous — it derives identity from the state row.
    private const string AnonymousMethod = "/donkeywork.vault.v1.OAuthFlow/Complete";

    public override Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        if (context.Method == AnonymousMethod)
        {
            return continuation(request, context);
        }

        var rawUser = context.RequestHeaders.GetValue("x-user-id");
        if (string.IsNullOrEmpty(rawUser) || !Guid.TryParse(rawUser, out var userId))
        {
            throw new RpcException(new Status(StatusCode.Unauthenticated, "Missing or invalid x-user-id metadata."));
        }

        Guid.TryParse(context.RequestHeaders.GetValue("x-tenant-id"), out var tenantId);
        VaultCallerContext.Set(userId, tenantId);

        return continuation(request, context);
    }
}
