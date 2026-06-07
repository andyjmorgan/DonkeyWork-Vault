using DonkeyWork.Vault.Core.Services;
using DonkeyWork.Vault.Proto.V1;
using Grpc.Core;

namespace DonkeyWork.Vault.Api.Services;

public sealed class OAuthProviderConfigsGrpcService(IOAuthProviderConfigService svc) : OAuthProviderConfigs.OAuthProviderConfigsBase
{
    public override async Task<ListOAuthConfigsResponse> List(Empty request, ServerCallContext context)
    {
        var resp = new ListOAuthConfigsResponse();
        foreach (var c in await svc.ListAsync(context.CancellationToken))
        {
            var item = new OAuthConfigItem
            {
                Id = c.Id.ToString(), Provider = c.Provider, ClientIdMasked = c.ClientIdMasked,
                RedirectUri = c.RedirectUri ?? string.Empty, CreatedAt = c.CreatedAt.ToString("o"),
            };
            item.Scopes.AddRange(c.Scopes);
            resp.Items.Add(item);
        }
        return resp;
    }

    public override async Task<OAuthConfigItem> Upsert(UpsertOAuthConfigRequest request, ServerCallContext context)
    {
        try
        {
            var id = await svc.UpsertAsync(
                request.Provider, request.ClientId,
                string.IsNullOrEmpty(request.ClientSecret) ? null : request.ClientSecret,
                request.Scopes.ToList(),
                string.IsNullOrEmpty(request.RedirectUri) ? null : request.RedirectUri,
                context.CancellationToken);
            return new OAuthConfigItem { Id = id.ToString(), Provider = request.Provider };
        }
        catch (CredentialValidationException ex)
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, ex.Message));
        }
    }

    public override async Task<DeleteResponse> Delete(DeleteByIdRequest request, ServerCallContext context)
    {
        if (!Guid.TryParse(request.Id, out var id))
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, "invalid id."));
        }
        return new DeleteResponse { Deleted = await svc.DeleteAsync(id, context.CancellationToken) };
    }
}
