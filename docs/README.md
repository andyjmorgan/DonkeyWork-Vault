# DonkeyWork Vault Documentation

DonkeyWork Vault is a credential vault for people, scripts, and agents. It stores API keys and OAuth tokens encrypted at rest, records credential usage, and serves credentials through the web app, REST API, and `dwvault` CLI.

Use these docs based on what you are trying to do:

- [Quick start](quick-start.md): create your first credential, log in with the CLI, and make your first call.
- [Web app guide](web-app.md): use Credentials, Providers, OAuth Connect, Audit trail, and Profile.
- [CLI guide](cli.md): install, log in, retrieve credentials, connect scripts, and manage access keys.
- [OAuth providers](oauth-providers.md): add built-in or custom OAuth/OIDC providers and connect accounts.
- [Self-hosting](self-hosting.md): run the vault container with Postgres and your own OIDC login provider.
- [Security and operations](security.md): encryption, access keys, scopes, audit logging, and rotation.
- [API access](api.md): call the REST API directly with an access key.

The hosted vault is available at:

```text
https://vault.donkeywork.dev
```

The CLI defaults to the hosted vault. For self-hosted instances, pass `--addr https://vault.example.com` or set `VAULT_ADDR`.

