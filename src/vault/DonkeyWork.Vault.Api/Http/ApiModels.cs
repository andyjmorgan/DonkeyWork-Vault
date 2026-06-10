using System.Collections.Generic;
using DonkeyWork.Vault.Contracts;

namespace DonkeyWork.Vault.Api.Http;

// Request/response contracts for the vault's HTTP/JSON API. These records are the authoritative
// source of the OpenAPI document — the Go and TypeScript clients are generated from the spec they
// produce, so their shape (and the camelCase wire form ASP.NET emits by default) is load-bearing.
// Field names mirror the REST surface the portal BFF exposed, so the SPA keeps working unchanged.

/// <summary>The authenticated caller's identity (JWT user or API-key owner).</summary>
public sealed record MeResponse(string? UserId, string TenantId, string? Email, string? Name);

/// <summary>Public runtime config the SPA reads before sign-in (anonymous).</summary>
public sealed record AppConfigResponse(string Authority, string ClientId, string Scopes, bool AuthEnabled);

// ---- stored API keys (self-describing credentials) ----

public sealed record ApiKeyDto(
    Guid Id,
    string Name,
    string? Description,
    string? BaseUrl,
    string? DocsUrl,
    string? Header,
    string? Prefix,
    string? Username,
    CredentialKind Kind,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastUsedAt);

public sealed record CreateApiKeyRequest(
    string Name,
    string? Secret,
    string? Description,
    string? BaseUrl,
    string? DocsUrl,
    string? Header,
    string? Prefix,
    string? Username,
    CredentialKind Kind);

public sealed record CreatedApiKeyResponse(Guid Id, string Name);

/// <summary>The revealed secret plus the assembled header — used by the SPA reveal modal and the CLI.</summary>
public sealed record RevealApiKeyResponse(
    string Secret,
    string Header,
    string HeaderValue,
    string Prefix,
    string BaseUrl,
    string DocsUrl,
    string Description,
    string Scheme,
    string Username,
    CredentialKind Kind);

/// <summary>CLI-lean credential shape (no secret) — the LLM/agent reads this to know how to send a key.</summary>
public sealed record CredentialShapeResponse(
    string Header,
    string Prefix,
    string BaseUrl,
    string DocsUrl,
    string Description,
    string Scheme,
    string Username,
    CredentialKind Kind);

// ---- access keys (scoped auth credentials; secret shown once) ----

public sealed record AccessKeyDto(
    Guid Id,
    string Name,
    string? Description,
    IReadOnlyList<string> Scopes,
    bool Enabled,
    string Prefix,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastUsedAt);

public sealed record CreateAccessKeyRequest(string Name, string? Description, IReadOnlyList<string>? Scopes);

/// <summary>The plaintext secret is returned ONCE here and never again.</summary>
public sealed record CreatedAccessKeyResponse(Guid Id, string Name, IReadOnlyList<string> Scopes, string Secret);

public sealed record SetEnabledRequest(bool Enabled);

public sealed record AccessKeyEnabledResponse(Guid Id, bool Enabled);

// ---- provider manifests (runtime catalog CRUD) ----

public sealed record OAuthScopeDto(string Value, string Description, string Category, bool Sensitive);

public sealed record OAuthManifestDto(
    string Key,
    string Name,
    string IconUrl,
    string DocsUrl,
    bool Builtin,
    bool Overridden,
    string AuthorizationEndpoint,
    string TokenEndpoint,
    string UserinfoEndpoint,
    string ScopeDelimiter,
    IReadOnlyList<string> DefaultScopes,
    IReadOnlyList<OAuthScopeDto> Scopes);

public sealed record UpsertOAuthManifestRequest(
    string Key,
    string? Name,
    string? IconUrl,
    string? DocsUrl,
    string? AuthorizationEndpoint,
    string? TokenEndpoint,
    string? UserinfoEndpoint,
    string? ScopeDelimiter,
    List<string>? DefaultScopes,
    List<OAuthScopeDto>? Scopes);

public sealed record DiscoverOidcRequest(string? Url);

public sealed record KeyResponse(string Key);

// ---- OAuth provider app configs ----

public sealed record OAuthConfigDto(
    Guid Id,
    string Provider,
    string ClientIdMasked,
    IReadOnlyList<string> Scopes,
    string? RedirectUri,
    DateTimeOffset CreatedAt);

public sealed record UpsertOAuthConfigRequest(
    string Provider,
    string ClientId,
    string? ClientSecret,
    IReadOnlyList<string>? Scopes,
    string? RedirectUri);

public sealed record OAuthConfigCreatedResponse(Guid Id, string Provider);

// ---- OAuth tokens (connected accounts) ----

public sealed record OAuthTokenDto(
    Guid Id,
    string Provider,
    string Account,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? LastRefreshedAt,
    IReadOnlyList<string> Scopes);

/// <summary>A live OAuth access token (auto-refreshed by the vault).</summary>
public sealed record OAuthAccessTokenResponse(string AccessToken, DateTimeOffset? ExpiresAt, IReadOnlyList<string> Scopes);

public sealed record ConnectResponse(string AuthorizeUrl);

// ---- audit trail ----

public sealed record AuditEventDto(
    Guid Id,
    string Type,
    string Outcome,
    Guid UserId,
    Guid TenantId,
    string? AccessKeyPrefix,
    string? AccessKeyName,
    string? SourceIp,
    string? TargetKind,
    string? TargetProvider,
    string? TargetAccount,
    string? TargetName,
    string Transport,
    string? Method,
    string? Detail,
    DateTimeOffset CreatedAt);

public sealed record AuditPageResponse(IReadOnlyList<AuditEventDto> Items, int Total, int Limit, int Offset);

/// <summary>Uniform error body for non-2xx responses.</summary>
public sealed record ErrorResponse(string Error);
