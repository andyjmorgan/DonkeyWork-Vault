using DonkeyWork.Vault.Core.Services;
using DonkeyWork.Vault.Proto.V1;
using Grpc.Core;

namespace DonkeyWork.Vault.Api.Services;

public sealed class CredentialStoreGrpcService(IApiKeyService apiKeys) : CredentialStore.CredentialStoreBase
{
    public override async Task<GetApiKeyResponse> GetApiKey(GetApiKeyRequest request, ServerCallContext context)
    {
        var name = string.IsNullOrEmpty(request.Name) ? null : request.Name;
        var result = await apiKeys.GetAsync(request.Provider, name, context.CancellationToken);
        if (result is null)
        {
            return new GetApiKeyResponse { Found = false };
        }

        var response = new GetApiKeyResponse { Found = true, Secret = result.Secret };
        foreach (var (k, v) in result.Fields)
        {
            response.Fields[k] = v;
        }
        return response;
    }

    public override Task<DescribeCredentialResponse> DescribeCredential(DescribeCredentialRequest request, ServerCallContext context)
    {
        var manifest = apiKeys.DescribeShape(request.Provider);
        if (manifest is null)
        {
            return Task.FromResult(new DescribeCredentialResponse { Found = false });
        }

        var shape = new CredentialShape
        {
            BaseUrl = manifest.BaseUrl,
            Header = manifest.Auth.Header,
            Prefix = manifest.Auth.Prefix,
        };
        foreach (var (k, v) in manifest.Auth.StaticHeaders)
        {
            shape.StaticHeaders[k] = v;
        }

        return Task.FromResult(new DescribeCredentialResponse { Found = true, Shape = shape });
    }
}
