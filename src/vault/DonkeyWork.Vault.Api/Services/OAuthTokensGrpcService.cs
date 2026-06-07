using DonkeyWork.Vault.Core.Services;
using DonkeyWork.Vault.Proto.V1;
using Grpc.Core;
using ProtoSummary = DonkeyWork.Vault.Proto.V1.OAuthTokenSummary;

namespace DonkeyWork.Vault.Api.Services;

public sealed class OAuthTokensGrpcService(IOAuthTokenService oauth) : OAuthTokens.OAuthTokensBase
{
    public override async Task<ListOAuthTokensResponse> List(ListOAuthTokensRequest request, ServerCallContext context)
    {
        var items = await oauth.ListAsync(context.CancellationToken);
        var response = new ListOAuthTokensResponse();
        foreach (var t in items)
        {
            var s = new ProtoSummary
            {
                Id = t.Id.ToString(),
                Provider = t.Provider,
                Account = t.Account,
                ExpiresAt = t.ExpiresAt?.ToString("o") ?? string.Empty,
                LastRefreshedAt = t.LastRefreshedAt?.ToString("o") ?? string.Empty,
            };
            s.Scopes.AddRange(t.Scopes);
            response.Items.Add(s);
        }
        return response;
    }
}
