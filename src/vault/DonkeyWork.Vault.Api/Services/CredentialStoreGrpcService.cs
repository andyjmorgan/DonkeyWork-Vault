using DonkeyWork.Vault.Core.Services;
using DonkeyWork.Vault.Proto.V1;
using Grpc.Core;

namespace DonkeyWork.Vault.Api.Services;

public sealed class CredentialStoreGrpcService(IApiKeyService apiKeys, IOAuthTokenService oauth) : CredentialStore.CredentialStoreBase
{
    public override async Task<GetApiKeyResponse> GetApiKey(GetApiKeyRequest request, ServerCallContext context)
    {
        var result = await apiKeys.GetByNameAsync(request.Name, context.CancellationToken);
        if (result is null)
        {
            return new GetApiKeyResponse { Found = false };
        }
        return new GetApiKeyResponse
        {
            Found = true,
            Secret = result.Secret,
            Header = result.Header ?? string.Empty,
            Prefix = result.Prefix ?? string.Empty,
            BaseUrl = result.BaseUrl ?? string.Empty,
            DocsUrl = result.DocsUrl ?? string.Empty,
            Description = result.Description ?? string.Empty,
        };
    }

    public override async Task<DescribeCredentialResponse> DescribeCredential(DescribeCredentialRequest request, ServerCallContext context)
    {
        var item = (await apiKeys.ListAsync(context.CancellationToken)).FirstOrDefault(k => k.Name == request.Name);
        if (item is null)
        {
            return new DescribeCredentialResponse { Found = false };
        }
        return new DescribeCredentialResponse
        {
            Found = true,
            Header = item.Header ?? string.Empty,
            Prefix = item.Prefix ?? string.Empty,
            BaseUrl = item.BaseUrl ?? string.Empty,
            DocsUrl = item.DocsUrl ?? string.Empty,
            Description = item.Description ?? string.Empty,
        };
    }

    public override async Task<GetOAuthAccessTokenResponse> GetOAuthAccessToken(GetOAuthAccessTokenRequest request, ServerCallContext context)
    {
        var account = string.IsNullOrEmpty(request.Account) ? null : request.Account;
        try
        {
            var token = await oauth.GetAccessTokenAsync(request.Provider, account, context.CancellationToken);
            if (token is null)
            {
                return new GetOAuthAccessTokenResponse { Found = false };
            }
            var resp = new GetOAuthAccessTokenResponse
            {
                Found = true,
                AccessToken = token.AccessToken,
                ExpiresAt = token.ExpiresAt?.ToString("o") ?? string.Empty,
            };
            resp.Scopes.AddRange(token.Scopes);
            return resp;
        }
        catch (OAuthRefreshException ex)
        {
            throw new RpcException(new Status(StatusCode.Unavailable, ex.Message));
        }
    }
}
