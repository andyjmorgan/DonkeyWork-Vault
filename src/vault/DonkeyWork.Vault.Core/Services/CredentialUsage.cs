using System.Text;

namespace DonkeyWork.Vault.Core.Services;

/// <summary>
/// Single source of truth for how a stored credential is presented to a caller — so the
/// shape (non-secret discovery) and the secret path agree on scheme and header assembly.
/// Presence of a username is the discriminator: username set ⇒ HTTP Basic, otherwise the
/// secret is sent verbatim behind <c>header</c>/<c>prefix</c>.
/// </summary>
public static class CredentialUsage
{
    public const string Basic = "basic";
    public const string Header = "header";

    /// <summary>The auth scheme implied by whether a username is present.</summary>
    public static string Scheme(string? username) =>
        string.IsNullOrEmpty(username) ? Header : Basic;

    /// <summary>
    /// The ready-to-send HTTP header for this credential. For Basic, emits
    /// <c>Authorization: Basic base64(username:secret)</c>; otherwise <c>{header}: {prefix}{secret}</c>.
    /// Contains secret material — only ever returned on the authenticated secret path.
    /// </summary>
    public static (string Name, string Value) AssembleHeader(string? header, string? prefix, string? username, string secret)
    {
        if (!string.IsNullOrEmpty(username))
        {
            var token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{secret}"));
            return (string.IsNullOrEmpty(header) ? "Authorization" : header, $"Basic {token}");
        }

        return (header ?? string.Empty, (prefix ?? string.Empty) + secret);
    }
}
