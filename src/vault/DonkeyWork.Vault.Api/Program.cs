using DonkeyWork.Vault.Api.Identity;
using DonkeyWork.Vault.Api.Services;
using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Core;
using DonkeyWork.Vault.Persistence;
using DonkeyWork.Vault.Persistence.Services;
using Microsoft.AspNetCore.Server.Kestrel.Core;

var builder = WebApplication.CreateBuilder(args);

// gRPC on 8080 as HTTP/2-only cleartext (h2c) — Kestrel does not serve h2c under
// Http1AndHttp2. /healthz lives on 8081 (HTTP/1.1) for the k8s httpGet probe.
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(8080, listen => listen.Protocols = HttpProtocols.Http2);
    options.ListenAnyIP(8081, listen => listen.Protocols = HttpProtocols.Http1);
});

builder.Services.AddSingleton<UserContextInterceptor>();
builder.Services.AddGrpc(options => options.Interceptors.Add<UserContextInterceptor>());
builder.Services.AddGrpcReflection();
builder.Services.AddHealthChecks();

builder.Services.AddSingleton<IVaultCallerContext, VaultCallerContext>();
builder.Services.AddVaultPersistence(builder.Configuration);
builder.Services.AddVaultCore();

var app = builder.Build();

// Apply migrations on startup (Postgres must be reachable).
using (var scope = app.Services.CreateScope())
{
    await scope.ServiceProvider.GetRequiredService<IMigrationService>().MigrateAsync();
}

app.MapGrpcService<CredentialStoreGrpcService>();
app.MapGrpcService<ApiKeysGrpcService>();
app.MapGrpcService<ApiKeyCatalogGrpcService>();
app.MapGrpcService<OAuthTokensGrpcService>();
app.MapGrpcReflectionService();

app.MapHealthChecks("/healthz");
app.MapGet("/", () => Results.Text("DonkeyWork Vault — internal gRPC service. No public surface."));

app.Run();
