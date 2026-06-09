using System.Security.Claims;
using DonkeyWork.Vault.Api.Http.Auth;
using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Contracts.Audit;
using DonkeyWork.Vault.Core.Audit;
using DonkeyWork.Vault.Core.Manifests;
using DonkeyWork.Vault.Core.Services;
using Microsoft.AspNetCore.Http.HttpResults;

namespace DonkeyWork.Vault.Api.Http.Endpoints;

/// <summary>
/// Maps the vault's HTTP/JSON API. Handlers call the Core services directly (no gRPC hop): the vault
/// is the single service. The route shapes and camelCase wire form match the surface the portal BFF
/// exposed, so the SPA keeps working unchanged. These typed handlers are the source of the OpenAPI
/// document the Go + TS clients are generated from.
/// </summary>
public static class VaultApiEndpoints
{
    public static void MapVaultApi(this WebApplication app, bool authConfigured, string publicBaseUrl, AppConfigResponse appConfig)
    {
        // Main surface: every authenticated caller is scope-gated (vault:read / vault:readwrite by
        // method). JWT users carry the full scope set; API keys carry their minted scopes.
        // Authorization is ALWAYS required — the default authentication scheme is the ApiKey handler
        // when OIDC is absent, so a missing OIDC authority can never leave the API anonymously open.
        var api = app.MapGroup("/api/v1");
        api.RequireAuthorization();
        api.AddEndpointFilter(new ScopeGateFilter());

        MapIdentity(api);
        MapApiKeys(api);
        MapCredentials(api);
        MapAccessKeys(api);
        MapManifests(api);
        MapOAuthConfigs(api);
        MapOAuthTokens(api, publicBaseUrl);

        // Audit read: gated by vault:audit (not the read/readwrite method gate).
        MapAudit(app, authConfigured);

        MapAnonymous(app, appConfig, publicBaseUrl);
    }

    // ---- identity ----

    private static void MapIdentity(RouteGroupBuilder api) =>
        api.MapGet("/me", (ClaimsPrincipal user) => TypedResults.Ok(new MeResponse(
            UserId: user.FindFirst("sub")?.Value ?? user.FindFirst(ClaimTypes.NameIdentifier)?.Value,
            TenantId: user.FindFirst("tenant_id")?.Value ?? "",
            Email: user.FindFirst("email")?.Value,
            Name: user.FindFirst("name")?.Value ?? user.FindFirst("preferred_username")?.Value)));

    // ---- stored API keys ----

    private static void MapApiKeys(RouteGroupBuilder api)
    {
        api.MapGet("/api-keys", async (IApiKeyService svc, CancellationToken ct) =>
            TypedResults.Ok((await svc.ListAsync(ct)).Select(ToApiKeyDto).ToList()));

        api.MapPost("/api-keys", async Task<Results<Ok<CreatedApiKeyResponse>, BadRequest<ErrorResponse>>> (
            CreateApiKeyRequest dto, IApiKeyService svc, CancellationToken ct) =>
        {
            try
            {
                var item = await svc.CreateAsync(dto.Name, dto.Secret ?? "", dto.Description, dto.BaseUrl, dto.DocsUrl, dto.Header, dto.Prefix, dto.Username, dto.Kind, ct);
                return TypedResults.Ok(new CreatedApiKeyResponse(item.Id, item.Name));
            }
            catch (CredentialValidationException ex)
            {
                return TypedResults.BadRequest(new ErrorResponse(ex.Message));
            }
        });

        api.MapDelete("/api-keys/{id:guid}", async Task<Results<NoContent, NotFound>> (Guid id, IApiKeyService svc, CancellationToken ct) =>
            await svc.DeleteAsync(id, ct) ? TypedResults.NoContent() : TypedResults.NotFound());

        // Reveal the stored secret + assembled header (SPA reveal modal; CLI `creds get`/`header`).
        api.MapGet("/api-keys/{name}/reveal", async Task<Results<Ok<RevealApiKeyResponse>, NotFound>> (
            string name, IApiKeyService svc, CancellationToken ct) =>
        {
            var s = await svc.GetByNameAsync(name, ct);
            if (s is null)
            {
                return TypedResults.NotFound();
            }
            var (header, headerValue) = CredentialUsage.AssembleHeader(s.Header, s.Prefix, s.Username, s.Secret);
            return TypedResults.Ok(new RevealApiKeyResponse(
                Secret: s.Secret, Header: header, HeaderValue: headerValue,
                Prefix: s.Prefix ?? "", BaseUrl: s.BaseUrl ?? "", DocsUrl: s.DocsUrl ?? "",
                Description: s.Description ?? "", Scheme: CredentialUsage.Scheme(s.Username), Username: s.Username ?? "", Kind: s.Kind));
        });
    }

    // ---- CLI-lean credential shape (no secret) ----

    private static void MapCredentials(RouteGroupBuilder api) =>
        api.MapGet("/credentials/{name}", async Task<Results<Ok<CredentialShapeResponse>, NotFound>> (
            string name, IApiKeyService svc, CancellationToken ct) =>
        {
            var item = (await svc.ListAsync(ct)).FirstOrDefault(k => k.Name == name);
            return item is null
                ? TypedResults.NotFound()
                : TypedResults.Ok(new CredentialShapeResponse(
                    Header: CredentialUsage.HeaderName(item.Header), Prefix: item.Prefix ?? "",
                    BaseUrl: item.BaseUrl ?? "", DocsUrl: item.DocsUrl ?? "", Description: item.Description ?? "",
                    Scheme: CredentialUsage.Scheme(item.Username), Username: item.Username ?? "", Kind: item.Kind));
        });

    // ---- access keys ----

    private static void MapAccessKeys(RouteGroupBuilder api)
    {
        api.MapGet("/access-keys", async (IAccessKeyService svc, CancellationToken ct) =>
            TypedResults.Ok((await svc.ListAsync(ct)).Select(ToAccessKeyDto).ToList()));

        api.MapPost("/access-keys", async Task<Results<Ok<CreatedAccessKeyResponse>, BadRequest<ErrorResponse>>> (
            CreateAccessKeyRequest dto, IAccessKeyService svc, CancellationToken ct) =>
        {
            try
            {
                var (key, secret) = await svc.CreateAsync(dto.Name, dto.Description, dto.Scopes ?? [], ct);
                return TypedResults.Ok(new CreatedAccessKeyResponse(key.Id, key.Name, key.Scopes, secret));
            }
            catch (CredentialValidationException ex)
            {
                return TypedResults.BadRequest(new ErrorResponse(ex.Message));
            }
        });

        api.MapPatch("/access-keys/{id:guid}", async Task<Results<Ok<AccessKeyEnabledResponse>, NotFound>> (
            Guid id, SetEnabledRequest dto, IAccessKeyService svc, CancellationToken ct) =>
        {
            var item = await svc.SetEnabledAsync(id, dto.Enabled, ct);
            return item is null ? TypedResults.NotFound() : TypedResults.Ok(new AccessKeyEnabledResponse(item.Id, item.Enabled));
        });

        api.MapDelete("/access-keys/{id:guid}", async Task<Results<NoContent, NotFound>> (Guid id, IAccessKeyService svc, CancellationToken ct) =>
            await svc.DeleteAsync(id, ct) ? TypedResults.NoContent() : TypedResults.NotFound());
    }

    // ---- OAuth provider manifests (runtime catalog CRUD) ----

    private static void MapManifests(RouteGroupBuilder api)
    {
        api.MapGet("/manifests", async (ManifestResolver m, CancellationToken ct) =>
        {
            var items = await m.ListOAuthAsync(ct);
            return TypedResults.Ok(items.Select(x => ToOAuthManifestDto(x, m.IsOAuthBuiltin(x.Key))).ToList());
        });

        api.MapPost("/manifests/oauth", async Task<Results<Ok<KeyResponse>, Conflict<ErrorResponse>>> (
            UpsertOAuthManifestRequest dto, ManifestResolver m, CancellationToken ct) =>
        {
            try
            {
                await m.UpsertOAuthAsync(FromOAuthManifestDto(dto), ct);
                return TypedResults.Ok(new KeyResponse(dto.Key));
            }
            catch (BuiltinManifestException ex)
            {
                return TypedResults.Conflict(new ErrorResponse(ex.Message));
            }
        });

        api.MapPost("/manifests/oauth/discover", async Task<Results<Ok<OAuthManifestDto>, BadRequest<ErrorResponse>>> (
            DiscoverOidcRequest dto, OAuthDiscoveryService discovery, CancellationToken ct) =>
        {
            try
            {
                var m = await discovery.DiscoverAsync(dto.Url ?? "", ct);
                return TypedResults.Ok(ToOAuthManifestDto(m, builtin: false));
            }
            catch (Exception ex)
            {
                return TypedResults.BadRequest(new ErrorResponse($"discovery failed: {ex.Message}"));
            }
        });

        api.MapDelete("/manifests/{kind}/{key}", async Task<Results<NoContent, NotFound>> (string kind, string key, ManifestResolver m, CancellationToken ct) =>
            await m.DeleteAsync(kind, key, ct) ? TypedResults.NoContent() : TypedResults.NotFound());
    }

    // ---- OAuth provider app configs ----

    private static void MapOAuthConfigs(RouteGroupBuilder api)
    {
        api.MapGet("/oauth/configs", async (IOAuthProviderConfigService c, CancellationToken ct) =>
            TypedResults.Ok((await c.ListAsync(ct)).Select(ToOAuthConfigDto).ToList()));

        api.MapPost("/oauth/configs", async Task<Results<Ok<OAuthConfigCreatedResponse>, BadRequest<ErrorResponse>>> (
            UpsertOAuthConfigRequest dto, IOAuthProviderConfigService c, CancellationToken ct) =>
        {
            try
            {
                var id = await c.UpsertAsync(dto.Provider, dto.ClientId, dto.ClientSecret, dto.Scopes ?? [], dto.RedirectUri, ct);
                return TypedResults.Ok(new OAuthConfigCreatedResponse(id, dto.Provider));
            }
            catch (CredentialValidationException ex)
            {
                return TypedResults.BadRequest(new ErrorResponse(ex.Message));
            }
        });

        api.MapDelete("/oauth/configs/{id:guid}", async Task<Results<NoContent, NotFound>> (Guid id, IOAuthProviderConfigService c, CancellationToken ct) =>
            await c.DeleteAsync(id, ct) ? TypedResults.NoContent() : TypedResults.NotFound());
    }

    // ---- OAuth tokens (connected accounts) + connect + live token ----

    private static void MapOAuthTokens(RouteGroupBuilder api, string publicBaseUrl)
    {
        api.MapGet("/oauth/tokens", async (IOAuthTokenService t, CancellationToken ct) =>
            TypedResults.Ok((await t.ListAsync(ct)).Select(ToOAuthTokenDto).ToList()));

        api.MapGet("/oauth/{provider}/token", async Task<Results<Ok<OAuthAccessTokenResponse>, NotFound, JsonHttpResult<ErrorResponse>>> (
            string provider, string? account, IOAuthTokenService t, CancellationToken ct) =>
        {
            try
            {
                var token = await t.GetAccessTokenAsync(provider, account, ct);
                return token is null
                    ? TypedResults.NotFound()
                    : TypedResults.Ok(new OAuthAccessTokenResponse(token.AccessToken, token.ExpiresAt, token.Scopes));
            }
            catch (OAuthRefreshException ex)
            {
                return TypedResults.Json(new ErrorResponse(ex.Message), statusCode: StatusCodes.Status502BadGateway);
            }
        });

        api.MapGet("/oauth/{provider}/connect", async Task<Results<Ok<ConnectResponse>, BadRequest<ErrorResponse>>> (
            string provider, IOAuthFlowService f, CancellationToken ct) =>
        {
            try
            {
                var r = await f.BeginAsync(provider, null, publicBaseUrl, ct);
                return TypedResults.Ok(new ConnectResponse(r.AuthorizeUrl));
            }
            catch (OAuthAuthorizationException ex)
            {
                return TypedResults.BadRequest(new ErrorResponse(ex.Message));
            }
        });
    }

    // ---- audit ----

    private static void MapAudit(WebApplication app, bool authConfigured)
    {
        var ep = app.MapGet("/api/v1/audit", async Task<Ok<AuditPageResponse>> (
            int? limit, int? offset, string? type, string? outcome, Guid? userId,
            DateTimeOffset? since, DateTimeOffset? until, IAuditQueryService svc, CancellationToken ct) =>
        {
            var query = new AuditQuery(
                Limit: limit ?? 50,
                Offset: offset ?? 0,
                Type: Enum.TryParse<AuditEventType>(type, ignoreCase: true, out var t) ? t : null,
                Outcome: Enum.TryParse<AuditOutcome>(outcome, ignoreCase: true, out var o) ? o : null,
                UserId: userId,
                Since: since,
                Until: until);
            var result = await svc.QueryAsync(query, ct);
            var items = result.Items.Select(ToAuditEventDto).ToList();
            return TypedResults.Ok(new AuditPageResponse(items, result.Total, result.Limit, result.Offset));
        }).AddEndpointFilter(new ScopeGateFilter("vault:audit"));

        ep.RequireAuthorization();
    }

    // ---- anonymous (no auth) ----

    private static void MapAnonymous(WebApplication app, AppConfigResponse appConfig, string publicBaseUrl)
    {
        // Public OAuth callback — identity derived from the state row, not the caller.
        app.MapGet("/api/oauth/{provider}/callback", async (string provider, string? code, string? state, string? error, IOAuthFlowService f, CancellationToken ct) =>
        {
            if (!string.IsNullOrEmpty(error))
            {
                return Results.Redirect($"/?oauth_error={Uri.EscapeDataString(error)}");
            }
            if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state))
            {
                return Results.Redirect("/?oauth_error=missing_code");
            }
            try
            {
                var r = await f.CompleteAsync(provider, code, state, ct);
                return Results.Redirect($"/?connected={Uri.EscapeDataString(r.Provider)}");
            }
            catch (OAuthAuthorizationException ex)
            {
                return Results.Redirect($"/?oauth_error={Uri.EscapeDataString(ex.Message)}");
            }
        }).AllowAnonymous();

        // Public runtime config for the SPA's OIDC login (read before sign-in).
        app.MapGet("/api/config", () => TypedResults.Ok(appConfig)).AllowAnonymous();
        _ = publicBaseUrl; // reserved for future anonymous endpoints that need it
    }

    // ---- mappers ----

    private static ApiKeyDto ToApiKeyDto(StoredApiKey k) => new(
        k.Id, k.Name, k.Description, k.BaseUrl, k.DocsUrl, k.Header, k.Prefix, k.Username, k.Kind, k.CreatedAt, k.LastUsedAt);

    private static AccessKeyDto ToAccessKeyDto(StoredAccessKey k) => new(
        k.Id, k.Name, k.Description, k.Scopes, k.Enabled, k.Prefix, k.CreatedAt, k.LastUsedAt);

    private static OAuthManifestDto ToOAuthManifestDto(OAuthManifest m, bool builtin) => new(
        m.Key, m.Name, m.IconUrl, m.DocsUrl, builtin, m.AuthorizationEndpoint, m.TokenEndpoint, m.UserinfoEndpoint,
        m.ScopeDelimiter, m.DefaultScopes,
        m.Scopes.Select(s => new OAuthScopeDto(s.Value, s.Description, s.Category, s.Sensitive)).ToList());

    private static OAuthManifest FromOAuthManifestDto(UpsertOAuthManifestRequest dto) => new()
    {
        Key = dto.Key, Name = dto.Name ?? "", IconUrl = dto.IconUrl ?? "", DocsUrl = dto.DocsUrl ?? "",
        AuthorizationEndpoint = dto.AuthorizationEndpoint ?? "", TokenEndpoint = dto.TokenEndpoint ?? "",
        UserinfoEndpoint = dto.UserinfoEndpoint ?? "", ScopeDelimiter = string.IsNullOrEmpty(dto.ScopeDelimiter) ? " " : dto.ScopeDelimiter,
        DefaultScopes = dto.DefaultScopes ?? [],
        Scopes = (dto.Scopes ?? []).Select(s => new OAuthScopeDef { Value = s.Value, Description = s.Description, Category = s.Category, Sensitive = s.Sensitive }).ToList(),
    };

    private static OAuthConfigDto ToOAuthConfigDto(OAuthConfigSummary i) => new(
        i.Id, i.Provider, i.ClientIdMasked, i.Scopes, i.RedirectUri, i.CreatedAt);

    private static OAuthTokenDto ToOAuthTokenDto(OAuthTokenSummary x) => new(
        x.Id, x.Provider, x.Account, x.ExpiresAt, x.LastRefreshedAt, x.Scopes);

    private static AuditEventDto ToAuditEventDto(AuditLogView a) => new(
        a.Id, a.Type.ToString(), a.Outcome.ToString(), a.UserId, a.TenantId,
        a.AccessKeyPrefix, a.AccessKeyName, a.SourceIp, a.TargetKind, a.TargetProvider, a.TargetAccount, a.TargetName,
        a.Transport, a.Method, a.Detail, a.CreatedAt);
}
