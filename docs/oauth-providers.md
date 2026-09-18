# OAuth Providers

DonkeyWork Vault can store OAuth provider definitions and OAuth app credentials, then connect user accounts through Authorization Code with PKCE.

The vault supports two kinds of provider setup:

- **Built-in templates**: start from a bundled provider definition, then save your own copy.
- **Custom OIDC discovery**: paste an issuer URL and let the vault discover endpoints and scopes from `.well-known/openid-configuration`.

## OAuth Setup Flow

1. Go to **Providers**.
2. Add a provider from the library or click **Add custom**.
3. Configure provider endpoints, scopes, authorize parameters, and app credentials.
4. Register the vault callback URL with the provider.
5. Go to **OAuth Connect**.
6. Select scopes and connect the account.
7. Use `dwvault oauth get <provider>` to retrieve live access tokens.

## Redirect URI

Register this callback URL in the provider's OAuth app:

```text
https://<your-vault-host>/api/oauth/callback
```

For the hosted vault:

```text
https://vault.donkeywork.dev/api/oauth/callback
```

The callback route is provider-agnostic. The vault stores provider and owner information in the OAuth state created at the start of the flow.

## Add a Built-In Template

1. Open **Providers**.
2. In **Library**, click **Add** next to the provider.
3. Review the slug, endpoints, scopes, and authorize parameters.
4. Enter the provider app's **Client ID** and **Client secret**.
5. Save.

Adding a template copies it into your provider list. After that, it is your editable provider definition.

## Add a Custom OIDC Provider

1. Open **Providers**.
2. Click **Add custom**.
3. Paste the issuer URL in **OIDC discovery URL**.
4. Click **Discover**.
5. Review or edit the generated slug, name, endpoints, scopes, and defaults.
6. Add client credentials.
7. Save.

If discovery fails, fill these fields manually:

- **Authorization endpoint**
- **Token endpoint**
- **Userinfo endpoint**, if available
- **Scope delimiter**, usually a single space
- **Scopes**

Provider slugs must contain only letters, digits, `_`, or `-`.

## Scopes

Scopes define what the provider may grant and what users can choose on **OAuth Connect**.

Each scope can include:

- **Value**: the exact OAuth scope string sent to the provider.
- **Description**: human-readable text shown in the connect UI.
- **Category**: grouping label in the connect UI.
- **Sensitive**: marks a high-risk scope.

When starting OAuth, the vault allowlists requested scopes against the provider's declared scope catalog and default scopes. Unknown scopes are dropped before the authorize URL is built.

## Authorize Parameters

Authorize parameters are extra query parameters added to the provider authorization URL.

Common examples:

| Provider behavior | Parameter examples |
|---|---|
| Request refresh tokens from Google | `access_type=offline`, `prompt=consent` |
| Request offline access from Dropbox | `token_access_type=offline` |

These parameters are provider-specific. Use the provider's OAuth docs to confirm exact names and values.

## Connect an Account

After provider configuration:

1. Open **OAuth Connect**.
2. Select the provider.
3. Choose scopes.
4. Click **Connect**.
5. Complete the provider authorization prompt.

The connected account appears in **OAuth Connect** and **Credentials**.

Use the CLI:

```bash
dwvault oauth list
dwvault oauth get github
dwvault oauth get microsoft --account alice@example.com
```

## Updating Provider Credentials

Open **Providers**, edit the provider, and enter a new client secret. Leaving client ID blank saves provider definition changes only and does not touch stored app credentials.

Removing provider credentials prevents new connects. Existing connected token records can be removed from **OAuth Connect**.

Deleting a provider removes that provider definition and its related app configs and connected tokens for your account.

## X API and MCP

The X template connects your X account using OAuth 2.0 Authorization Code with
PKCE. Vault encrypts the access and refresh tokens and refreshes access tokens
when you retrieve them. This is user-context access, so calls use your account's
granted permissions.

### Register and connect your app

1. Create an app in the [X Developer Console](https://developer.x.com).
2. Enable OAuth 2.0. Choose a confidential client type, such as Web App or Automated App / bot.
3. Register `https://vault.donkeywork.dev/api/oauth/callback` as an exact callback URL.
4. In Vault, open **Providers**, add **X** from the library, and enter the app's OAuth 2.0 client ID and client secret.
5. Keep the template's HTTP Basic token authentication and `data.username` account field, then save.
6. Open **OAuth Connect**, select X, choose scopes, and connect in your browser.

Use the OAuth 2.0 client credentials, not OAuth 1.0a consumer keys or an app-only
bearer token. This template supports confidential apps, which can keep a client
secret securely on the Vault server.

The default scopes are `tweet.read users.read offline.access`. X uses
`offline.access`, not `offline_access`, to issue a refresh token. Access tokens
normally last two hours. Add `bookmark.read` and `bookmark.write` for bookmark
management, or `tweet.write` for posting through supported API endpoints. Select
only the scopes you need, and reconnect when adding scopes.

### Provider and connection shape

| Setting | Value |
| --- | --- |
| Vault provider slug | `x` |
| Authorization URL | `https://x.com/i/oauth2/authorize` |
| Token and refresh URL | `https://api.x.com/2/oauth2/token` |
| Token endpoint authentication | `client_secret_basic` for confidential apps |
| PKCE method | `S256` |
| Scope delimiter | A space |
| Account lookup | `GET https://api.x.com/2/users/me` |
| Account field | `data.username` |
| API authentication | `Authorization: Bearer <user access token>` |
| MCP URL | `https://api.x.com/mcp` |
| MCP transport | Streamable HTTP |
| Documented MCP protocol version | `2025-06-18` |

X's account response is nested, for example:

```json
{"data":{"id":"123","name":"Alice","username":"alice"}}
```

Vault uses the username as the connected account label. For example,
`dwvault oauth get x --account alice` retrieves that account's current token.

### Use the token with the X API

This example passes the token straight to X without printing it:

```bash
curl --fail-with-body https://api.x.com/2/users/me \
  -H "Authorization: Bearer $(dwvault oauth get x)"
```

For multiple connected accounts, add `--account <username>` to the token command.

### Use the token with MCP

X provides an official hosted MCP server at `https://api.x.com/mcp`. It does not
advertise native MCP OAuth discovery or support dynamic client registration.
Configure your MCP client with that URL and an `Authorization: Bearer` header
supplied from Vault. The MCP client must support external bearer tokens.

For a client that accepts a token from an environment variable:

```bash
export X_ACCESS_TOKEN="$(dwvault oauth get x)"
# Configure the client to use X_ACCESS_TOKEN as its bearer token, then launch it.
```

This exports a snapshot of the token. Vault refreshes tokens on retrieval;
changing a stored token does not update an already running client's environment.
For long-running sessions, use a client or bridge that retrieves a fresh token
from Vault before expiry. Do not paste a token into a committed MCP configuration.

A protocol-level handshake can be checked with:

```bash
curl --fail-with-body https://api.x.com/mcp \
  -H "Authorization: Bearer $(dwvault oauth get x)" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"vault-check","version":"1.0"}}}'
```

This only initializes a connection; an MCP client handles the remaining session
messages and tool calls. The documented tools cover search, posts, users,
bookmarks, trends, news, and Articles. Available operations depend on your scopes
and X app entitlement. X documents `client-not-enrolled` as requiring the app's
Pay-per-use package and Production environment.

X's recommended `xurl mcp` bridge is another option, but it manages its own login
and refresh-token cache. Vault does not configure that cache. The separate
`https://docs.x.com/mcp` endpoint searches documentation; it does not call the X API.

### Sources

Verified against X's official documentation on September 18, 2026:

- [X MCP server and authentication](https://docs.x.com/tools/mcp)
- [OAuth 2.0 scopes and token lifetime](https://docs.x.com/fundamentals/authentication/oauth-2-0/authorization-code)
- [PKCE token exchange and client authentication](https://docs.x.com/fundamentals/authentication/oauth-2-0/user-access-token)
