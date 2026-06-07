using DonkeyWork.Vault.Core.Services;
using DonkeyWork.Vault.Proto.V1;
using Grpc.Core;

namespace DonkeyWork.Vault.Api.Services;

public sealed class OAuthFlowGrpcService(IOAuthFlowService flow) : OAuthFlow.OAuthFlowBase
{
    public override async Task<BeginAuthResponse> Begin(BeginAuthRequest request, ServerCallContext context)
    {
        try
        {
            var res = await flow.BeginAsync(
                request.Provider,
                request.Scopes.Count > 0 ? request.Scopes.ToList() : null,
                string.IsNullOrEmpty(request.PublicBaseUrl) ? "https://vault.donkeywork.dev" : request.PublicBaseUrl,
                context.CancellationToken);
            return new BeginAuthResponse { AuthorizeUrl = res.AuthorizeUrl, State = res.State };
        }
        catch (OAuthAuthorizationException ex)
        {
            throw new RpcException(new Status(StatusCode.FailedPrecondition, ex.Message));
        }
    }

    public override async Task<CompleteAuthResponse> Complete(CompleteAuthRequest request, ServerCallContext context)
    {
        try
        {
            var res = await flow.CompleteAsync(request.Provider, request.Code, request.State, context.CancellationToken);
            var resp = new CompleteAuthResponse
            {
                Provider = res.Provider, Account = res.Account, ExpiresAt = res.ExpiresAt?.ToString("o") ?? string.Empty,
            };
            resp.Scopes.AddRange(res.Scopes);
            return resp;
        }
        catch (OAuthAuthorizationException ex)
        {
            throw new RpcException(new Status(StatusCode.FailedPrecondition, ex.Message));
        }
    }
}
