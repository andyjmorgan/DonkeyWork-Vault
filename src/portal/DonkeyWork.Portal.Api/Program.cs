var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHealthChecks();

var app = builder.Build();

// Serve the vendored SPA (single container: BFF + static frontend).
app.UseDefaultFiles();
app.UseStaticFiles();

app.MapHealthChecks("/healthz");
app.MapGet("/api/health", () => Results.Ok(new { status = "ok", service = "portal" }));

// SPA fallback — any non-API route serves index.html.
app.MapFallbackToFile("index.html");

app.Run();
