using System.Security.Claims;
using DonkeyWork.Portal.Api.Auth;
using DonkeyWork.Portal.Api.Vault;
using DonkeyWork.Vault.Proto.V1;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

// The vault speaks gRPC over cleartext HTTP/2 (h2c); allow unencrypted HTTP/2 for the client.
AppContext.SetSwitch("System.Net.Http.SocketsHttpHandler.Http2UnencryptedSupport", true);

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpContextAccessor();
builder.Services.AddHealthChecks();

var keycloak = builder.Configuration.GetSection(KeycloakOptions.SectionName).Get<KeycloakOptions>() ?? new KeycloakOptions();
var authConfigured = !string.IsNullOrWhiteSpace(keycloak.Authority);

if (authConfigured)
{
    builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
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
}
builder.Services.AddAuthorization();

// Vault gRPC clients (h2c). UserIdInterceptor forwards the caller's identity.
builder.Services.AddScoped<UserIdInterceptor>();
var vaultEndpoint = builder.Configuration["Vault:GrpcEndpoint"] ?? "http://localhost:8080";
void AddVaultClient<T>() where T : class
    => builder.Services.AddGrpcClient<T>(o => o.Address = new Uri(vaultEndpoint)).AddInterceptor<UserIdInterceptor>();
AddVaultClient<CredentialStore.CredentialStoreClient>();
AddVaultClient<ApiKeys.ApiKeysClient>();
AddVaultClient<ApiKeyCatalog.ApiKeyCatalogClient>();

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

if (authConfigured)
{
    app.UseAuthentication();
    app.UseAuthorization();
}

app.MapHealthChecks("/healthz");

var api = app.MapGroup("/api/v1");
if (authConfigured)
{
    api.RequireAuthorization();
}

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
    return Results.Ok(resp.Items.Select(k => new { k.Id, k.Provider, k.Name, k.CreatedAt, k.LastUsedAt }));
});

api.MapPost("/api-keys", async (CreateApiKeyDto dto, ApiKeys.ApiKeysClient client) =>
{
    try
    {
        var req = new CreateApiKeyRequest { Provider = dto.Provider, Name = dto.Name };
        foreach (var (k, v) in dto.Fields ?? new())
        {
            req.Fields[k] = v;
        }
        var item = await client.CreateAsync(req);
        return Results.Ok(new { item.Id, item.Provider, item.Name, item.CreatedAt });
    }
    catch (Grpc.Core.RpcException ex) when (ex.StatusCode == Grpc.Core.StatusCode.InvalidArgument)
    {
        return Results.BadRequest(new { error = ex.Status.Detail });
    }
    catch (Grpc.Core.RpcException ex) when (ex.StatusCode == Grpc.Core.StatusCode.NotFound)
    {
        return Results.BadRequest(new { error = ex.Status.Detail });
    }
});

api.MapDelete("/api-keys/{id}", async (string id, ApiKeys.ApiKeysClient client) =>
{
    var resp = await client.DeleteAsync(new DeleteApiKeyRequest { Id = id });
    return resp.Deleted ? Results.NoContent() : Results.NotFound();
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

internal sealed record CreateApiKeyDto(string Provider, string Name, Dictionary<string, string>? Fields);
