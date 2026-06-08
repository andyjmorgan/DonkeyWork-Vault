using DonkeyWork.Vault.Core.Services;
using DonkeyWork.Vault.Proto.V1;
using Grpc.Core;

namespace DonkeyWork.Vault.Api.Services;

public sealed class AccessKeysGrpcService(IAccessKeyService accessKeys) : AccessKeys.AccessKeysBase
{
    public override async Task<ListAccessKeysResponse> List(Empty request, ServerCallContext context)
    {
        var items = await accessKeys.ListAsync(context.CancellationToken);
        var response = new ListAccessKeysResponse();
        response.Items.AddRange(items.Select(ToItem));
        return response;
    }

    public override async Task<CreateAccessKeyResponse> Create(CreateAccessKeyRequest request, ServerCallContext context)
    {
        try
        {
            var (key, secret) = await accessKeys.CreateAsync(
                request.Name, request.Description, request.Scopes.ToList(), context.CancellationToken);
            return new CreateAccessKeyResponse { Item = ToItem(key), Secret = secret };
        }
        catch (CredentialValidationException ex)
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, ex.Message));
        }
    }

    public override async Task<AccessKeyItem> SetEnabled(SetAccessKeyEnabledRequest request, ServerCallContext context)
    {
        if (!Guid.TryParse(request.Id, out var id))
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, "invalid id."));
        }
        var updated = await accessKeys.SetEnabledAsync(id, request.Enabled, context.CancellationToken);
        if (updated is null)
        {
            throw new RpcException(new Status(StatusCode.NotFound, "no such access key."));
        }
        return ToItem(updated);
    }

    public override async Task<DeleteResponse> Delete(DeleteByIdRequest request, ServerCallContext context)
    {
        if (!Guid.TryParse(request.Id, out var id))
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, "invalid id."));
        }
        var deleted = await accessKeys.DeleteAsync(id, context.CancellationToken);
        return new DeleteResponse { Deleted = deleted };
    }

    public override async Task<AuthenticateApiKeyResponse> Authenticate(AuthenticateApiKeyRequest request, ServerCallContext context)
    {
        var principal = await accessKeys.AuthenticateAsync(request.Secret, context.CancellationToken);
        if (principal is null)
        {
            return new AuthenticateApiKeyResponse { Valid = false };
        }
        var response = new AuthenticateApiKeyResponse
        {
            Valid = true,
            UserId = principal.UserId.ToString(),
            TenantId = principal.TenantId == Guid.Empty ? string.Empty : principal.TenantId.ToString(),
            Name = principal.Name,
        };
        response.Scopes.AddRange(principal.Scopes);
        return response;
    }

    private static AccessKeyItem ToItem(StoredAccessKey k)
    {
        var item = new AccessKeyItem
        {
            Id = k.Id.ToString(),
            Name = k.Name,
            Description = k.Description ?? string.Empty,
            Enabled = k.Enabled,
            Prefix = k.Prefix,
            CreatedAt = k.CreatedAt.ToString("o"),
            LastUsedAt = k.LastUsedAt?.ToString("o") ?? string.Empty,
        };
        item.Scopes.AddRange(k.Scopes);
        return item;
    }
}
