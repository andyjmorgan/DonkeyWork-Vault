using DonkeyWork.Vault.Core.Manifests;
using DonkeyWork.Vault.Proto.V1;
using Grpc.Core;

namespace DonkeyWork.Vault.Api.Services;

public sealed class ApiKeyCatalogGrpcService(ManifestResolver manifests) : ApiKeyCatalog.ApiKeyCatalogBase
{
    public override async Task<ListProvidersResponse> ListProviders(ListProvidersRequest request, ServerCallContext context)
    {
        var response = new ListProvidersResponse();
        response.Providers.AddRange((await manifests.ListApiKeyAsync(context.CancellationToken)).Select(ToProto));
        return response;
    }

    public override async Task<ApiKeyProvider> GetProvider(GetProviderRequest request, ServerCallContext context)
    {
        var manifest = await manifests.GetApiKeyAsync(request.Key, context.CancellationToken)
            ?? throw new RpcException(new Status(StatusCode.NotFound, $"Unknown provider '{request.Key}'."));
        return ToProto(manifest);
    }

    private static ApiKeyProvider ToProto(ApiKeyManifest m)
    {
        var p = new ApiKeyProvider
        {
            Key = m.Key,
            Name = m.Name,
            IconUrl = m.IconUrl,
            DocsUrl = m.DocsUrl,
            AuthScheme = m.Auth.Scheme,
            Header = m.Auth.Header,
            Prefix = m.Auth.Prefix,
            BaseUrl = m.BaseUrl,
        };
        foreach (var (k, v) in m.Auth.StaticHeaders)
        {
            p.StaticHeaders[k] = v;
        }
        p.Fields.AddRange(m.Fields.Select(f => new ApiKeyField
        {
            Name = f.Name,
            Label = f.Label,
            Secret = f.Secret,
            Required = f.Required,
        }));
        return p;
    }
}
