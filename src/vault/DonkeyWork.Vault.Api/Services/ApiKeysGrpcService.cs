using DonkeyWork.Vault.Core.Services;
using DonkeyWork.Vault.Proto.V1;
using Grpc.Core;

namespace DonkeyWork.Vault.Api.Services;

public sealed class ApiKeysGrpcService(IApiKeyService apiKeys) : ApiKeys.ApiKeysBase
{
    public override async Task<ListApiKeysResponse> List(ListApiKeysRequest request, ServerCallContext context)
    {
        var items = await apiKeys.ListAsync(context.CancellationToken);
        var response = new ListApiKeysResponse();
        response.Items.AddRange(items.Select(ToItem));
        return response;
    }

    public override async Task<ApiKeyItem> Create(CreateApiKeyRequest request, ServerCallContext context)
    {
        try
        {
            var stored = await apiKeys.CreateAsync(
                request.Name, request.Secret, request.Description, request.BaseUrl, request.DocsUrl,
                request.Header, request.Prefix, request.Username, context.CancellationToken);
            return ToItem(stored);
        }
        catch (CredentialValidationException ex)
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, ex.Message));
        }
    }

    public override async Task<DeleteApiKeyResponse> Delete(DeleteApiKeyRequest request, ServerCallContext context)
    {
        if (!Guid.TryParse(request.Id, out var id))
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, "invalid id."));
        }
        var deleted = await apiKeys.DeleteAsync(id, context.CancellationToken);
        return new DeleteApiKeyResponse { Deleted = deleted };
    }

    private static ApiKeyItem ToItem(StoredApiKey k) => new()
    {
        Id = k.Id.ToString(),
        Name = k.Name,
        Description = k.Description ?? string.Empty,
        BaseUrl = k.BaseUrl ?? string.Empty,
        DocsUrl = k.DocsUrl ?? string.Empty,
        Header = k.Header ?? string.Empty,
        Prefix = k.Prefix ?? string.Empty,
        Username = k.Username ?? string.Empty,
        CreatedAt = k.CreatedAt.ToString("o"),
        LastUsedAt = k.LastUsedAt?.ToString("o") ?? string.Empty,
    };
}
