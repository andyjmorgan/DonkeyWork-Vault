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

