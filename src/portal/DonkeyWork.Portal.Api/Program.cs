using System.Security.Claims;
using DonkeyWork.Portal.Api.Auth;
using DonkeyWork.Portal.Api.Vault;
using DonkeyWork.Vault.Proto.V1;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

// The vault speaks gRPC over cleartext HTTP/2 (h2c); allow unencrypted HTTP/2 for the client.
AppContext.SetSwitch("System.Net.Http.SocketsHttpHandler.Http2UnencryptedSupport", true);

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpContextAccessor();
builder.Services.AddHealthChecks();

var keycloak = builder.Configuration.GetSection(KeycloakOptions.SectionName).Get<KeycloakOptions>() ?? new KeycloakOptions();
var authConfigured = !string.IsNullOrWhiteSpace(keycloak.Authority);

// Two ways in: interactive users via Keycloak JWT, and scripts/agents via an access key
// (dwv_…). A policy scheme routes each request to the right handler so HttpContext.User is set
// from whichever credential was presented. The ApiKey scheme is always available.
var authBuilder = builder.Services.AddAuthentication(authConfigured ? "Multi" : ApiKeyAuthenticationHandler.SchemeName);
authBuilder.AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(ApiKeyAuthenticationHandler.SchemeName, null);
if (authConfigured)
{
    authBuilder.AddJwtBearer(options =>
        {
            options.Authority = keycloak.Authority;
            options.MetadataAddress = $"{(keycloak.InternalAuthority ?? keycloak.Authority).TrimEnd('/')}/.well-known/openid-configuration";
            options.RequireHttpsMetadata = keycloak.RequireHttpsMetadata;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidIssuer = keycloak.Authority,
                ValidateAudience = false, // Keycloak puts client id in azp; audience varies
                NameClaimType = "sub",
            };
        });
    authBuilder.AddPolicyScheme("Multi", "JWT or API key", o =>
    {
        o.ForwardDefaultSelector = ctx =>
        {
            if (!string.IsNullOrEmpty(ctx.Request.Headers["X-Api-Key"]))
            {
                return ApiKeyAuthenticationHandler.SchemeName;
            }
            var auth = ctx.Request.Headers.Authorization.ToString();
            return auth.StartsWith("Bearer " + ApiKeyAuthenticationHandler.KeyPrefix, StringComparison.OrdinalIgnoreCase)
                ? ApiKeyAuthenticationHandler.SchemeName
                : JwtBearerDefaults.AuthenticationScheme;
        };
    });
}
builder.Services.AddAuthorization();

// Vault gRPC clients (h2c). UserIdInterceptor forwards the caller's identity.
builder.Services.AddScoped<UserIdInterceptor>();
var vaultEndpoint = builder.Configuration["Vault:GrpcEndpoint"] ?? "http://localhost:8080";
void AddVaultClient<T>() where T : class
    => builder.Services.AddGrpcClient<T>(o => o.Address = new Uri(vaultEndpoint)).AddInterceptor<UserIdInterceptor>();
AddVaultClient<CredentialStore.CredentialStoreClient>();
AddVaultClient<ApiKeys.ApiKeysClient>();
AddVaultClient<AccessKeys.AccessKeysClient>();
AddVaultClient<ApiKeyCatalog.ApiKeyCatalogClient>();
AddVaultClient<Manifests.ManifestsClient>();
AddVaultClient<OAuthProviderConfigs.OAuthProviderConfigsClient>();
AddVaultClient<OAuthFlow.OAuthFlowClient>();
AddVaultClient<OAuthTokens.OAuthTokensClient>();

var publicBaseUrl = builder.Configuration["Portal:PublicBaseUrl"] ?? "https://vault.donkeywork.dev";

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

// Always on: the ApiKey scheme is registered even when Keycloak isn't, so keys authenticate
// (and their scopes are enforced) in every configuration.
app.UseAuthentication();
app.UseAuthorization();

app.MapHealthChecks("/healthz");

var api = app.MapGroup("/api/v1");
if (authConfigured)
{
    api.RequireAuthorization();
}

// Scope gate for API-key callers: GET/HEAD need frontend:read, mutations need frontend:readwrite
// (readwrite implies read). Interactive JWT users are not scope-limited.
api.AddEndpointFilter(async (ctx, next) =>
{
    var user = ctx.HttpContext.User;
    if (user.Identity?.AuthenticationType == ApiKeyAuthenticationHandler.SchemeName)
    {
        var method = ctx.HttpContext.Request.Method;
        var required = HttpMethods.IsGet(method) || HttpMethods.IsHead(method) || HttpMethods.IsOptions(method)
            ? "frontend:read"
            : "frontend:readwrite";
        var scopes = user.FindAll("scope").Select(c => c.Value).ToHashSet();
        if (!scopes.Contains(required) && !scopes.Contains("frontend:readwrite"))
        {
            return Results.Json(new { error = $"API key missing required scope '{required}'." }, statusCode: StatusCodes.Status403Forbidden);
        }
    }
    return await next(ctx);
});

api.MapGet("/me", (ClaimsPrincipal user) => Results.Ok(new
{
    userId = user.FindFirst("sub")?.Value ?? user.FindFirst(ClaimTypes.NameIdentifier)?.Value,
    tenantId = user.FindFirst("tenant_id")?.Value ?? "",
    email = user.FindFirst("email")?.Value,
    name = user.FindFirst("name")?.Value ?? user.FindFirst("preferred_username")?.Value,
}));

api.MapGet("/providers", async (ApiKeyCatalog.ApiKeyCatalogClient client) =>
{
    var resp = await client.ListProvidersAsync(new ListProvidersRequest());
    return Results.Ok(resp.Providers.Select(MapProvider));
});

api.MapGet("/providers/{key}", async (string key, ApiKeyCatalog.ApiKeyCatalogClient client) =>
{
    try
    {
        var p = await client.GetProviderAsync(new GetProviderRequest { Key = key });
        return Results.Ok(MapProvider(p));
    }
    catch (Grpc.Core.RpcException ex) when (ex.StatusCode == Grpc.Core.StatusCode.NotFound)
    {
        return Results.NotFound();
    }
});

api.MapGet("/api-keys", async (ApiKeys.ApiKeysClient client) =>
{
    var resp = await client.ListAsync(new ListApiKeysRequest());
    return Results.Ok(resp.Items.Select(k => new { k.Id, k.Name, k.Description, k.BaseUrl, k.DocsUrl, k.Header, k.Prefix, k.CreatedAt, k.LastUsedAt }));
});

api.MapPost("/api-keys", async (CreateApiKeyDto dto, ApiKeys.ApiKeysClient client) =>
{
    try
    {
        var item = await client.CreateAsync(new CreateApiKeyRequest
        {
            Name = dto.Name, Secret = dto.Secret ?? "", Description = dto.Description ?? "",
            BaseUrl = dto.BaseUrl ?? "", DocsUrl = dto.DocsUrl ?? "", Header = dto.Header ?? "", Prefix = dto.Prefix ?? "",
        });
        return Results.Ok(new { item.Id, item.Name });
    }
    catch (Grpc.Core.RpcException ex) when (ex.StatusCode == Grpc.Core.StatusCode.InvalidArgument)
    {
        return Results.BadRequest(new { error = ex.Status.Detail });
    }
});

api.MapDelete("/api-keys/{id}", async (string id, ApiKeys.ApiKeysClient client) =>
{
    var resp = await client.DeleteAsync(new DeleteApiKeyRequest { Id = id });
    return resp.Deleted ? Results.NoContent() : Results.NotFound();
});

// reveal the stored secret (authed user, on demand)
api.MapGet("/api-keys/{name}/reveal", async (string name, CredentialStore.CredentialStoreClient cs) =>
{
    var r = await cs.GetApiKeyAsync(new GetApiKeyRequest { Name = name });
    return r.Found ? Results.Ok(new { secret = r.Secret }) : Results.NotFound();
});

// reveal a live OAuth access token (auto-refreshed by the vault)
api.MapGet("/oauth/{provider}/token", async (string provider, string? account, CredentialStore.CredentialStoreClient cs) =>
{
    try
    {
        var r = await cs.GetOAuthAccessTokenAsync(new GetOAuthAccessTokenRequest { Provider = provider, Account = account ?? "" });
        return r.Found ? Results.Ok(new { accessToken = r.AccessToken, expiresAt = r.ExpiresAt }) : Results.NotFound();
    }
    catch (Grpc.Core.RpcException ex)
    {
        return Results.BadRequest(new { error = ex.Status.Detail });
    }
});

// ---- access keys (scoped auth credentials; secret shown once on create) ----
api.MapGet("/access-keys", async (AccessKeys.AccessKeysClient client) =>
{
    var resp = await client.ListAsync(new Empty());
    return Results.Ok(resp.Items.Select(k => new
    {
        k.Id, k.Name, k.Description, scopes = k.Scopes, k.Enabled, k.Prefix, k.CreatedAt, k.LastUsedAt,
    }));
});

api.MapPost("/access-keys", async (CreateAccessKeyDto dto, AccessKeys.AccessKeysClient client) =>
{
    var req = new CreateAccessKeyRequest { Name = dto.Name, Description = dto.Description ?? "" };
    if (dto.Scopes is not null) req.Scopes.AddRange(dto.Scopes);
    try
    {
        var resp = await client.CreateAsync(req);
        // The plaintext secret is returned ONCE here and never again.
        return Results.Ok(new { resp.Item.Id, resp.Item.Name, scopes = resp.Item.Scopes, secret = resp.Secret });
    }
    catch (Grpc.Core.RpcException ex) when (ex.StatusCode == Grpc.Core.StatusCode.InvalidArgument)
    {
        return Results.BadRequest(new { error = ex.Status.Detail });
    }
});

api.MapPatch("/access-keys/{id}", async (string id, SetEnabledDto dto, AccessKeys.AccessKeysClient client) =>
{
    try
    {
        var item = await client.SetEnabledAsync(new SetAccessKeyEnabledRequest { Id = id, Enabled = dto.Enabled });
        return Results.Ok(new { item.Id, item.Enabled });
    }
    catch (Grpc.Core.RpcException ex) when (ex.StatusCode == Grpc.Core.StatusCode.NotFound)
    {
        return Results.NotFound();
    }
});

api.MapDelete("/access-keys/{id}", async (string id, AccessKeys.AccessKeysClient client) =>
{
    var resp = await client.DeleteAsync(new DeleteByIdRequest { Id = id });
    return resp.Deleted ? Results.NoContent() : Results.NotFound();
});

// ---- provider manifests (runtime catalog CRUD) ----
api.MapGet("/manifests", async (string? kind, Manifests.ManifestsClient m) =>
{
    if (kind == "oauth")
    {
        var r = await m.ListOAuthAsync(new Empty());
        return Results.Ok(r.Items.Select(x => new
        {
            x.Key, x.Name, x.IconUrl, x.DocsUrl, x.Builtin, x.AuthorizationEndpoint, x.TokenEndpoint, x.UserinfoEndpoint, x.ScopeDelimiter,
            defaultScopes = x.DefaultScopes,
            scopes = x.Scopes.Select(s => new { s.Value, s.Description, s.Category, s.Sensitive }),
        }));
    }
    var a = await m.ListApiKeyAsync(new Empty());
    return Results.Ok(a.Items.Select(MapProvider));
});

api.MapPost("/manifests/apikey", async (ApiKeyManifestDto dto, Manifests.ManifestsClient m) =>
{
    var p = new ApiKeyProvider
    {
        Key = dto.Key, Name = dto.Name, IconUrl = dto.IconUrl ?? "", DocsUrl = dto.DocsUrl ?? "",
        AuthScheme = dto.AuthScheme ?? "header", Header = dto.Header ?? "", Prefix = dto.Prefix ?? "", BaseUrl = dto.BaseUrl ?? "",
    };
    foreach (var (k, v) in dto.StaticHeaders ?? new()) p.StaticHeaders[k] = v;
    foreach (var f in dto.Fields ?? new()) p.Fields.Add(new ApiKeyField { Name = f.Name, Label = f.Label ?? "", Secret = f.Secret, Required = f.Required });
    return Results.Ok(MapProvider(await m.UpsertApiKeyAsync(p)));
});

api.MapPost("/manifests/oauth", async (OAuthManifestDto dto, Manifests.ManifestsClient m) =>
{
    var msg = new OAuthManifestMsg
    {
        Key = dto.Key, Name = dto.Name ?? "", IconUrl = dto.IconUrl ?? "", DocsUrl = dto.DocsUrl ?? "",
        AuthorizationEndpoint = dto.AuthorizationEndpoint ?? "",
        TokenEndpoint = dto.TokenEndpoint ?? "", UserinfoEndpoint = dto.UserinfoEndpoint ?? "", ScopeDelimiter = dto.ScopeDelimiter ?? " ",
    };
    if (dto.DefaultScopes is not null) msg.DefaultScopes.AddRange(dto.DefaultScopes);
    foreach (var s in dto.Scopes ?? new()) msg.Scopes.Add(new OAuthScopeMsg { Value = s.Value, Description = s.Description ?? "", Category = s.Category ?? "", Sensitive = s.Sensitive });
    await m.UpsertOAuthAsync(msg);
    return Results.Ok(new { dto.Key });
});

api.MapPost("/manifests/oauth/discover", async (DiscoverDto dto, Manifests.ManifestsClient m) =>
{
    try
    {
        var x = await m.DiscoverOidcAsync(new DiscoverOidcRequest { Url = dto.Url ?? "" });
        return Results.Ok(new
        {
            x.Key, x.Name, x.AuthorizationEndpoint, x.TokenEndpoint, x.UserinfoEndpoint, x.ScopeDelimiter,
            defaultScopes = x.DefaultScopes,
            scopes = x.Scopes.Select(s => new { s.Value, s.Description, s.Category, s.Sensitive }),
        });
    }
    catch (Grpc.Core.RpcException ex) when (ex.StatusCode == Grpc.Core.StatusCode.InvalidArgument)
    {
        return Results.BadRequest(new { error = ex.Status.Detail });
    }
});

api.MapDelete("/manifests/{kind}/{key}", async (string kind, string key, Manifests.ManifestsClient m) =>
{
    var r = await m.DeleteAsync(new DeleteManifestRequest { Kind = kind, Key = key });
    return r.Deleted ? Results.NoContent() : Results.NotFound();
});

// ---- oauth provider app configs ----
api.MapGet("/oauth/configs", async (OAuthProviderConfigs.OAuthProviderConfigsClient c) =>
{
    var r = await c.ListAsync(new Empty());
    return Results.Ok(r.Items.Select(i => new { i.Id, i.Provider, clientIdMasked = i.ClientIdMasked, scopes = i.Scopes, i.RedirectUri, i.CreatedAt }));
});
api.MapPost("/oauth/configs", async (OAuthConfigDto dto, OAuthProviderConfigs.OAuthProviderConfigsClient c) =>
{
    var req = new UpsertOAuthConfigRequest { Provider = dto.Provider, ClientId = dto.ClientId, ClientSecret = dto.ClientSecret ?? "", RedirectUri = dto.RedirectUri ?? "" };
    if (dto.Scopes is not null) req.Scopes.AddRange(dto.Scopes);
    try { var i = await c.UpsertAsync(req); return Results.Ok(new { i.Id, i.Provider }); }
    catch (Grpc.Core.RpcException ex) when (ex.StatusCode == Grpc.Core.StatusCode.InvalidArgument) { return Results.BadRequest(new { error = ex.Status.Detail }); }
});
api.MapDelete("/oauth/configs/{id}", async (string id, OAuthProviderConfigs.OAuthProviderConfigsClient c) =>
{
    var r = await c.DeleteAsync(new DeleteByIdRequest { Id = id });
    return r.Deleted ? Results.NoContent() : Results.NotFound();
});

// ---- oauth tokens (connected accounts) ----
api.MapGet("/oauth/tokens", async (OAuthTokens.OAuthTokensClient t) =>
{
    var r = await t.ListAsync(new ListOAuthTokensRequest());
    return Results.Ok(r.Items.Select(x => new { x.Id, x.Provider, x.Account, x.ExpiresAt, x.LastRefreshedAt, scopes = x.Scopes }));
});

// ---- oauth connect (returns authorize URL; SPA redirects the browser) ----
api.MapGet("/oauth/{provider}/connect", async (string provider, OAuthFlow.OAuthFlowClient f) =>
{
    try { var r = await f.BeginAsync(new BeginAuthRequest { Provider = provider, PublicBaseUrl = publicBaseUrl }); return Results.Ok(new { authorizeUrl = r.AuthorizeUrl }); }
    catch (Grpc.Core.RpcException ex) when (ex.StatusCode == Grpc.Core.StatusCode.FailedPrecondition) { return Results.BadRequest(new { error = ex.Status.Detail }); }
});

// ---- public OAuth callback (anonymous; identity derived from state) ----
app.MapGet("/api/oauth/{provider}/callback", async (string provider, string? code, string? state, string? error, OAuthFlow.OAuthFlowClient f) =>
{
    if (!string.IsNullOrEmpty(error)) return Results.Redirect($"/?oauth_error={Uri.EscapeDataString(error)}");
    if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state)) return Results.Redirect("/?oauth_error=missing_code");
    try { var r = await f.CompleteAsync(new CompleteAuthRequest { Provider = provider, Code = code, State = state }); return Results.Redirect($"/?connected={Uri.EscapeDataString(r.Provider)}"); }
    catch (Grpc.Core.RpcException ex) { return Results.Redirect($"/?oauth_error={Uri.EscapeDataString(ex.Status.Detail)}"); }
});

app.MapFallbackToFile("index.html");

app.Run();

static object MapProvider(ApiKeyProvider p) => new
{
    p.Key,
    p.Name,
    p.IconUrl,
    p.DocsUrl,
    authScheme = p.AuthScheme,
    p.Header,
    p.Prefix,
    p.BaseUrl,
    staticHeaders = p.StaticHeaders,
    fields = p.Fields.Select(f => new { f.Name, f.Label, f.Secret, f.Required }),
};

internal sealed record CreateApiKeyDto(string Name, string? Secret, string? Description, string? BaseUrl, string? DocsUrl, string? Header, string? Prefix);
internal sealed record CreateAccessKeyDto(string Name, string? Description, List<string>? Scopes);
internal sealed record SetEnabledDto(bool Enabled);
internal sealed record ApiKeyFieldDto(string Name, string? Label, bool Secret, bool Required);
internal sealed record ApiKeyManifestDto(string Key, string Name, string? IconUrl, string? DocsUrl, string? AuthScheme, string? Header, string? Prefix, string? BaseUrl, Dictionary<string, string>? StaticHeaders, List<ApiKeyFieldDto>? Fields);
internal sealed record OAuthScopeDto(string Value, string? Description, string? Category, bool Sensitive);
internal sealed record OAuthManifestDto(string Key, string? Name, string? IconUrl, string? DocsUrl, string? AuthorizationEndpoint, string? TokenEndpoint, string? UserinfoEndpoint, string? ScopeDelimiter, List<string>? DefaultScopes, List<OAuthScopeDto>? Scopes);
internal sealed record DiscoverDto(string? Url);
internal sealed record OAuthConfigDto(string Provider, string ClientId, string? ClientSecret, List<string>? Scopes, string? RedirectUri);
