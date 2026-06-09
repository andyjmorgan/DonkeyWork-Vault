using System.Security.Claims;
using DonkeyWork.Vault.Api.Http.Auth;
using DonkeyWork.Vault.Contracts.Audit;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace DonkeyWork.Vault.Integration.Tests;

/// <summary>
/// The scope gate must enforce for EVERY authenticated scheme. Regression target: JWT callers used to
/// bypass it entirely (it only acted on the ApiKey scheme), so a logged-in portal user was unscoped.
/// </summary>
public sealed class ScopeGateFilterTests
{
    private const string JwtScheme = "Bearer";
    private static readonly object Allowed = new();

    private static HttpContext Ctx(string method, string authType, params string[] scopes)
    {
        var identity = new ClaimsIdentity(scopes.Select(s => new Claim("scope", s)), authType, "sub", roleType: null);
        var services = new ServiceCollection();
        services.AddSingleton<IAuditLog, CapturingAuditLog>();
        services.AddSingleton<IAuditContextAccessor>(new FixedAuditContext());
        var http = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(identity),
            RequestServices = services.BuildServiceProvider(),
        };
        http.Request.Method = method;
        return http;
    }

    private static async Task<object?> Invoke(HttpContext http, string? fixedScope = null)
    {
        var filter = new ScopeGateFilter(fixedScope);
        var ctx = EndpointFilterInvocationContext.Create(http);
        EndpointFilterDelegate next = _ => ValueTask.FromResult<object?>(Allowed);
        return await filter.InvokeAsync(ctx, next);
    }

    private static bool Denied(object? result) => !ReferenceEquals(result, Allowed);

    [Fact]
    public async Task JwtCaller_WithoutRequiredScope_IsDenied()
    {
        // POST needs vault:readwrite; this JWT only has vault:read. Before the fix it would have passed.
        var http = Ctx("POST", JwtScheme, "vault:read");
        var result = await Invoke(http);

        Assert.True(Denied(result));
        var log = (CapturingAuditLog)http.RequestServices.GetRequiredService<IAuditLog>();
        Assert.Contains(log.Events, e => e.Type == AuditEventType.AuthFailed);
    }

    [Fact]
    public async Task JwtCaller_WithReadWrite_IsAllowed_OnMutation()
    {
        var http = Ctx("POST", JwtScheme, "vault:read", "vault:readwrite");
        Assert.Same(Allowed, await Invoke(http));
    }

    [Fact]
    public async Task JwtCaller_WithAudit_IsAllowed_OnAuditGatedEndpoint()
    {
        var http = Ctx("GET", JwtScheme, "vault:read", "vault:readwrite", "vault:audit");
        Assert.Same(Allowed, await Invoke(http, fixedScope: "vault:audit"));
    }

    [Fact]
    public async Task JwtCaller_WithoutAudit_IsDenied_OnAuditGatedEndpoint()
    {
        // readwrite does NOT imply audit — audit is a standalone scope.
        var http = Ctx("GET", JwtScheme, "vault:read", "vault:readwrite");
        Assert.True(Denied(await Invoke(http, fixedScope: "vault:audit")));
    }

    [Fact]
    public async Task ApiKeyCaller_WithoutAudit_IsDenied_OnAuditGatedEndpoint()
    {
        var http = Ctx("GET", VaultApiKeyAuthenticationHandler.SchemeName, "vault:read");
        Assert.True(Denied(await Invoke(http, fixedScope: "vault:audit")));
    }

    [Fact]
    public async Task ReadWrite_ImpliesRead_OnGet()
    {
        var http = Ctx("GET", JwtScheme, "vault:readwrite");
        Assert.Same(Allowed, await Invoke(http));
    }
}
