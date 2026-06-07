using DonkeyWork.Vault.Api.Identity;
using DonkeyWork.Vault.Api.Services;
using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Core;
using DonkeyWork.Vault.Persistence;
using DonkeyWork.Vault.Persistence.Services;
using Microsoft.AspNetCore.Server.Kestrel.Core;

var builder = WebApplication.CreateBuilder(args);

// gRPC-only internal service. HTTP/1+2 cleartext on 8080: gRPC over h2c + /healthz over HTTP/1.
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(8080, listen => listen.Protocols = HttpProtocols.Http1AndHttp2);
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
app.MapGrpcReflectionService();

app.MapHealthChecks("/healthz");
app.MapGet("/", () => Results.Text("DonkeyWork Vault — internal gRPC service. No public surface."));

app.Run();
