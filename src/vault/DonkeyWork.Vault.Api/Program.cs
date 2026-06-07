using Microsoft.AspNetCore.Server.Kestrel.Core;

var builder = WebApplication.CreateBuilder(args);

// gRPC-only internal service. HTTP/1+2 cleartext on 8080: gRPC over h2c, plus
// plain HTTP for the /healthz probe (k8s httpGet uses HTTP/1.1).
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(8080, listen => listen.Protocols = HttpProtocols.Http1AndHttp2);
});

builder.Services.AddGrpc();
builder.Services.AddGrpcReflection();
builder.Services.AddHealthChecks();

var app = builder.Build();

app.MapHealthChecks("/healthz");
app.MapGrpcReflectionService(); // skeleton: reflection on so grpcurl can introspect

// No public ingress — this service is reachable only inside the cluster network.
app.MapGet("/", () => Results.Text("DonkeyWork Vault — internal gRPC service. No public surface."));

app.Run();
