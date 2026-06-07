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
            var fields = request.Fields.ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);
            var stored = await apiKeys.CreateAsync(request.Provider, request.Name, fields, context.CancellationToken);
            return ToItem(stored);
        }
        catch (ManifestNotFoundException ex)
        {
            throw new RpcException(new Status(StatusCode.NotFound, ex.Message));
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
        Provider = k.Provider,
        Name = k.Name,
        CreatedAt = k.CreatedAt.ToString("o"),
        LastUsedAt = k.LastUsedAt?.ToString("o") ?? string.Empty,
    };
}
