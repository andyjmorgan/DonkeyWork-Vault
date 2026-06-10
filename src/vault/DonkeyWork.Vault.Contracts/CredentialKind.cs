using System.Text.Json.Serialization;

namespace DonkeyWork.Vault.Contracts;

/// <summary>
/// Explicit credential kind — the discriminator that tells an agent how to use the stored
/// secret. Serialized as a snake_case string on both the API (JSON) and the entity (a text
/// column via <see cref="CredentialKindExtensions"/>), never as an integer.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<CredentialKind>))]
public enum CredentialKind
{
    /// <summary>Catch-all: the secret is opaque material, returned verbatim (HMAC secrets, tokens with no header, …).</summary>
    [JsonStringEnumMemberName("opaque")]
    Opaque = 0,

    /// <summary>API key sent in an HTTP header: <c>{header}: {prefix}{secret}</c>.</summary>
    [JsonStringEnumMemberName("header_api_key")]
    HeaderApiKey,

    /// <summary>HTTP Basic: <c>Authorization: Basic base64(username:secret)</c>.</summary>
    [JsonStringEnumMemberName("http_basic")]
    HttpBasic,

    /// <summary>A username + password login that is NOT sent as HTTP Basic (e.g. an OAuth
    /// ROPC password grant, a DSM/query-param login, a DB user) — username is metadata,
    /// the secret is the password; no header is assembled.</summary>
    [JsonStringEnumMemberName("username_password")]
    UsernamePassword,

    /// <summary>SSH login: username + host (base_url = <c>ssh://host:port</c>); secret is the password or key.</summary>
    [JsonStringEnumMemberName("ssh")]
    Ssh,

    /// <summary>The whole connection string / DSN is the secret; returned verbatim.</summary>
    [JsonStringEnumMemberName("connection_string")]
    ConnectionString,
}

/// <summary>Snake_case wire mapping for <see cref="CredentialKind"/>, used for the entity's text column.</summary>
public static class CredentialKindExtensions
{
    public static string ToWire(this CredentialKind kind) => kind switch
    {
        CredentialKind.HeaderApiKey => "header_api_key",
        CredentialKind.HttpBasic => "http_basic",
        CredentialKind.UsernamePassword => "username_password",
        CredentialKind.Ssh => "ssh",
        CredentialKind.ConnectionString => "connection_string",
        _ => "opaque",
    };

    public static CredentialKind FromWire(string? wire) => wire switch
    {
        "header_api_key" => CredentialKind.HeaderApiKey,
        "http_basic" => CredentialKind.HttpBasic,
        "username_password" => CredentialKind.UsernamePassword,
        "ssh" => CredentialKind.Ssh,
        "connection_string" => CredentialKind.ConnectionString,
        _ => CredentialKind.Opaque,
    };
}
