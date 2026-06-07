using DonkeyWork.Vault.Core.Manifests;
using DonkeyWork.Vault.Proto.V1;
using Grpc.Core;

namespace DonkeyWork.Vault.Api.Services;

public sealed class ManifestsGrpcService(ManifestResolver resolver) : Manifests.ManifestsBase
{
    public override async Task<ListApiKeyManifestsResponse> ListApiKey(Empty request, ServerCallContext context)
    {
        var resp = new ListApiKeyManifestsResponse();
        resp.Items.AddRange((await resolver.ListApiKeyAsync(context.CancellationToken)).Select(ToApiProto));
        return resp;
    }

    public override async Task<ApiKeyProvider> UpsertApiKey(ApiKeyProvider request, ServerCallContext context)
    {
        await resolver.UpsertApiKeyAsync(FromApiProto(request), context.CancellationToken);
        var m = await resolver.GetApiKeyAsync(request.Key, context.CancellationToken);
        return m is null ? request : ToApiProto(m);
    }

    public override async Task<ListOAuthManifestsResponse> ListOAuth(Empty request, ServerCallContext context)
    {
        var resp = new ListOAuthManifestsResponse();
        resp.Items.AddRange((await resolver.ListOAuthAsync(context.CancellationToken)).Select(ToOAuthProto));
        return resp;
    }

    public override async Task<OAuthManifestMsg> UpsertOAuth(OAuthManifestMsg request, ServerCallContext context)
    {
        await resolver.UpsertOAuthAsync(FromOAuthProto(request), context.CancellationToken);
        return request;
    }

    public override async Task<DeleteResponse> Delete(DeleteManifestRequest request, ServerCallContext context) =>
        new() { Deleted = await resolver.DeleteAsync(request.Kind, request.Key, context.CancellationToken) };

    private static ApiKeyProvider ToApiProto(ApiKeyManifest m)
    {
        var p = new ApiKeyProvider
        {
            Key = m.Key, Name = m.Name, IconUrl = m.IconUrl, DocsUrl = m.DocsUrl,
            AuthScheme = m.Auth.Scheme, Header = m.Auth.Header, Prefix = m.Auth.Prefix, BaseUrl = m.BaseUrl,
        };
        foreach (var (k, v) in m.Auth.StaticHeaders) p.StaticHeaders[k] = v;
        p.Fields.AddRange(m.Fields.Select(f => new ApiKeyField { Name = f.Name, Label = f.Label, Secret = f.Secret, Required = f.Required }));
        return p;
    }

    private static ApiKeyManifest FromApiProto(ApiKeyProvider p) => new()
    {
        Key = p.Key, Name = p.Name, IconUrl = p.IconUrl, DocsUrl = p.DocsUrl, BaseUrl = p.BaseUrl,
        Auth = new ApiKeyAuth
        {
            Scheme = string.IsNullOrEmpty(p.AuthScheme) ? "header" : p.AuthScheme,
            Header = p.Header, Prefix = p.Prefix,
            StaticHeaders = p.StaticHeaders.ToDictionary(k => k.Key, v => v.Value),
        },
        Fields = p.Fields.Select(f => new ApiKeyFieldDef { Name = f.Name, Label = f.Label, Secret = f.Secret, Required = f.Required }).ToList(),
    };

    private static OAuthManifestMsg ToOAuthProto(OAuthManifest m)
    {
        var x = new OAuthManifestMsg
        {
            Key = m.Key, Name = m.Name, AuthorizationEndpoint = m.AuthorizationEndpoint,
            TokenEndpoint = m.TokenEndpoint, UserinfoEndpoint = m.UserinfoEndpoint, ScopeDelimiter = m.ScopeDelimiter,
        };
        x.DefaultScopes.AddRange(m.DefaultScopes);
        return x;
    }

    private static OAuthManifest FromOAuthProto(OAuthManifestMsg m) => new()
    {
        Key = m.Key, Name = m.Name, AuthorizationEndpoint = m.AuthorizationEndpoint,
        TokenEndpoint = m.TokenEndpoint, UserinfoEndpoint = m.UserinfoEndpoint,
        ScopeDelimiter = string.IsNullOrEmpty(m.ScopeDelimiter) ? " " : m.ScopeDelimiter,
        DefaultScopes = m.DefaultScopes.ToList(),
    };
}
