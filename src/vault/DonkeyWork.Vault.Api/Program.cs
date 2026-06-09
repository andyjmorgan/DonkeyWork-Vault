using DonkeyWork.Vault.Api.Http;
using DonkeyWork.Vault.Api.Http.Audit;
using DonkeyWork.Vault.Api.Http.Auth;
using DonkeyWork.Vault.Api.Http.Endpoints;
using DonkeyWork.Vault.Api.Identity;
using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Core;
using DonkeyWork.Vault.Core.Audit;
using DonkeyWork.Vault.Persistence;
using DonkeyWork.Vault.Persistence.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpContextAccessor();
builder.Services.AddHealthChecks();

// Caller identity + Core (services, crypto, audit) + persistence.
builder.Services.AddSingleton<IVaultCallerContext, VaultCallerContext>();
builder.Services.AddVaultPersistence(builder.Configuration);
builder.Services.AddVaultCore();

// OIDC config — `Oidc:` section, falling back to the legacy `Keycloak:` section (deprecated).
var oidc = builder.Configuration.GetSection(OidcOptions.SectionName).Get<OidcOptions>() ?? new OidcOptions();
if (string.IsNullOrWhiteSpace(oidc.Authority))
{
    var legacy = builder.Configuration.GetSection(OidcOptions.LegacySectionName).Get<OidcOptions>();
    if (legacy is not null && !string.IsNullOrWhiteSpace(legacy.Authority))
    {
        oidc = legacy;
    }
}
var spaClientId = string.IsNullOrWhiteSpace(oidc.ClientId) ? oidc.Audience : oidc.ClientId;
var authConfigured = !string.IsNullOrWhiteSpace(oidc.Authority);

// Scopes granted to an interactive JWT (portal) login. A portal user is the trusted human/admin, so
// they carry the full set — including vault:audit — and are then subject to the same scope gate as an
// API key. API keys, by contrast, carry only the scopes they were explicitly minted with.
string[] jwtUserScopes = ["vault:read", "vault:readwrite", "vault:audit"];

// Two ways in: interactive users via an OIDC JWT, and scripts/agents via a dwv_ access key. A policy
// scheme routes each request to the right handler so HttpContext.User is set from whichever credential
// was presented. The ApiKey scheme is always available (so keys + their scopes work in every config).
var authBuilder = builder.Services.AddAuthentication(authConfigured ? "Multi" : VaultApiKeyAuthenticationHandler.SchemeName);
authBuilder.AddScheme<AuthenticationSchemeOptions, VaultApiKeyAuthenticationHandler>(VaultApiKeyAuthenticationHandler.SchemeName, null);
if (authConfigured)
{
    authBuilder.AddJwtBearer(options =>
    {
        options.Authority = oidc.Authority;
        options.MetadataAddress = $"{(oidc.InternalAuthority ?? oidc.Authority).TrimEnd('/')}/.well-known/openid-configuration";
        options.RequireHttpsMetadata = oidc.RequireHttpsMetadata;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = oidc.Authority,
            ValidateAudience = false, // many IdPs put the client id in azp; audience varies
            NameClaimType = "sub",
        };
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = ctx =>
            {
                // Materialise the portal user's scopes onto the principal so the unified scope gate
                // (which now enforces for JWT and API-key callers alike) authorises them. Without this
                // a JWT caller would carry no "scope" claims and be denied every gated endpoint.
                if (ctx.Principal?.Identity is ClaimsIdentity id)
                {
                    foreach (var scope in jwtUserScopes)
                    {
                        id.AddClaim(new Claim("scope", scope));
                    }
                }
                return Task.CompletedTask;
            },
        };
    });
    authBuilder.AddPolicyScheme("Multi", "JWT or API key", o =>
    {
        o.ForwardDefaultSelector = ctx =>
        {
            if (!string.IsNullOrEmpty(ctx.Request.Headers["X-Api-Key"]))
            {
                return VaultApiKeyAuthenticationHandler.SchemeName;
            }
            var auth = ctx.Request.Headers.Authorization.ToString();
            return auth.StartsWith("Bearer " + VaultApiKeyAuthenticationHandler.KeyPrefix, StringComparison.OrdinalIgnoreCase)
                ? VaultApiKeyAuthenticationHandler.SchemeName
                : JwtBearerDefaults.AuthenticationScheme;
        };
    });
}
builder.Services.AddAuthorization();

// Emit OpenAPI 3.0 (not 3.1): the Go (oapi-codegen) and TS (openapi-typescript) generators both
// consume 3.0 cleanly, and the document is the authoritative contract those clients derive from.
builder.Services.AddOpenApi(options => options.OpenApiVersion = Microsoft.OpenApi.OpenApiSpecVersion.OpenApi3_0);

// Public HTTP edge: cap request volume per client IP so a flood of (DB-backed) auth attempts or API
// calls can't exhaust resources. The limit is generous — well above any legitimate human / CLI /
// agent usage — and only the API surface is limited; static SPA assets are unrestricted.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
    {
        if (!ctx.Request.Path.StartsWithSegments("/api"))
        {
            return RateLimitPartition.GetNoLimiter("static");
        }
        var key = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return RateLimitPartition.GetFixedWindowLimiter(key, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 600,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
        });
    });
});

// Correct RemoteIpAddress to the real client behind the k3s ingress. Only forwarded headers from a
// trusted immediate peer (Vault:Audit:TrustedProxies — the ingress / Service / lab subnets) are
// honoured; otherwise a client could spoof X-Forwarded-For and forge the audited source IP.
builder.Services.Configure<ForwardedHeadersOptions>(opts =>
{
    opts.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    opts.ForwardLimit = null;
    opts.KnownNetworks.Clear();
    opts.KnownProxies.Clear();

    var trusted = builder.Configuration
        .GetSection($"{AuditOptions.SectionName}:TrustedProxies")
        .Get<string[]>() ?? Array.Empty<string>();
    foreach (var cidr in trusted)
    {
        var net = TrustedNetwork.TryParse(cidr);
        if (net is null)
        {
            continue;
        }
        if (net.PrefixLength == 32 || net.PrefixLength == 128)
        {
            opts.KnownProxies.Add(net.Prefix);
        }
        else
        {
#pragma warning disable CS0618 // KnownNetworks uses the (still-supported) HttpOverrides.IPNetwork.
            opts.KnownNetworks.Add(new Microsoft.AspNetCore.HttpOverrides.IPNetwork(net.Prefix, net.PrefixLength));
#pragma warning restore CS0618
        }
    }
});

var publicBaseUrl = builder.Configuration["Vault:PublicBaseUrl"]
    ?? builder.Configuration["Portal:PublicBaseUrl"]
    ?? "https://vault.donkeywork.dev";
var appConfig = new AppConfigResponse(oidc.Authority, spaClientId, oidc.Scopes, authConfigured);

var app = builder.Build();

// Must run before anything reads the client IP so the audit trail records the real client.
app.UseForwardedHeaders();

// Apply migrations on startup (Postgres must be reachable). Skippable so the OpenAPI document can be
// emitted (codegen / drift gate) without a live database.
if (builder.Configuration.GetValue("Vault:RunMigrationsOnStartup", true))
{
    using var scope = app.Services.CreateScope();
    await scope.ServiceProvider.GetRequiredService<IMigrationService>().MigrateAsync();
}

// Shed excess load before auth/DB work (uses the forwarded-corrected client IP).
app.UseRateLimiter();

app.UseDefaultFiles();
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();

// After auth: publish the caller identity + audit metadata (IP, redacted headers, key reference) so
// the domain services see them. Outer to the endpoints, so the AsyncLocal flows down into Core.
app.UseMiddleware<AuditContextMiddleware>();

app.MapOpenApi();
app.MapHealthChecks("/healthz");
app.MapVaultApi(authConfigured, publicBaseUrl, appConfig);
app.MapFallbackToFile("index.html");

app.Run();
