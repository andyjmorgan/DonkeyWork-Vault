using System.Net;
using DonkeyWork.Vault.Api.Identity;
using DonkeyWork.Vault.Api.Services;
using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Core;
using DonkeyWork.Vault.Core.Audit;
using DonkeyWork.Vault.Persistence;
using DonkeyWork.Vault.Persistence.Services;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Server.Kestrel.Core;

var builder = WebApplication.CreateBuilder(args);

// gRPC on 8080 as HTTP/2-only cleartext (h2c) — Kestrel does not serve h2c under
// Http1AndHttp2. /healthz lives on 8081 (HTTP/1.1) for the k8s httpGet probe.
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(8080, listen => listen.Protocols = HttpProtocols.Http2);
    options.ListenAnyIP(8081, listen => listen.Protocols = HttpProtocols.Http1);
});

builder.Services.AddOptions<VaultAuthOptions>().BindConfiguration(VaultAuthOptions.SectionName);
builder.Services.AddSingleton<UserContextInterceptor>();
builder.Services.AddGrpc(options => options.Interceptors.Add<UserContextInterceptor>());
builder.Services.AddGrpcReflection();
builder.Services.AddHealthChecks();

builder.Services.AddSingleton<IVaultCallerContext, VaultCallerContext>();
builder.Services.AddVaultPersistence(builder.Configuration);
builder.Services.AddVaultCore();

// Correct RemoteIpAddress to the real client behind k3s ingress. Only forwarded headers from a
// trusted immediate peer (Vault:Audit:TrustedProxies, the ingress / Service / lab subnets) are
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

var app = builder.Build();

// Must run before the gRPC endpoint so the interceptor sees the corrected client IP.
app.UseForwardedHeaders();

// Apply migrations on startup (Postgres must be reachable).
using (var scope = app.Services.CreateScope())
{
    await scope.ServiceProvider.GetRequiredService<IMigrationService>().MigrateAsync();
}

app.MapGrpcService<CredentialStoreGrpcService>();
app.MapGrpcService<ApiKeysGrpcService>();
app.MapGrpcService<AccessKeysGrpcService>();
app.MapGrpcService<ApiKeyCatalogGrpcService>();
app.MapGrpcService<OAuthTokensGrpcService>();
app.MapGrpcService<ManifestsGrpcService>();
app.MapGrpcService<OAuthProviderConfigsGrpcService>();
app.MapGrpcService<OAuthFlowGrpcService>();
app.MapGrpcReflectionService();

app.MapHealthChecks("/healthz");
app.MapGet("/", () => Results.Text("DonkeyWork Vault — internal gRPC service. No public surface."));

app.Run();
