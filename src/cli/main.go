// dwvault — DonkeyWork Vault credential CLI.
//
// Talks to the Vault HTTP API. User auth is OAuth device login by default; autonomous
// callers can use a dwvault API key (dwv_...) via --api-key / VAULT_API_KEY. Stored
// credentials live in the OS keyring, or a 0600 file fallback.
//
// Output discipline: the requested secret/token goes to STDOUT only (no decoration,
// safe for shell substitution). All logs, prompts and errors go to STDERR. A miss or
// error exits non-zero.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"donkeywork.dev/vault-cli/internal/vaultapi"
)

var version = "dev" // set via -ldflags -X main.version on release builds

var (
	addr     string
	apiKey   string
	doUpdate bool
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "dwvault: "+format+"\n", a...)
	os.Exit(1)
}

// reqCtx returns a context with the standard request timeout.
func reqCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 20*time.Second)
}

// apiError formats a non-2xx HTTP response for stderr (never includes secrets).
func apiError(op string, status string, body []byte) error {
	if msg := errorMessage(body); msg != "" {
		return fmt.Errorf("%s: %s (%s)", op, msg, status)
	}
	return fmt.Errorf("%s: %s", op, status)
}

// errorMessage pulls the `error` field out of an ErrorResponse body, if present.
func errorMessage(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil {
		return e.Error
	}
	return ""
}

func main() {
	root := &cobra.Command{
		Use:           "dwvault",
		Short:         "DonkeyWork Vault credential CLI",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		// Best-effort passive update notice; never blocks or fails the real command.
		PersistentPreRun: func(cmd *cobra.Command, _ []string) { maybeNotifyUpdate(cmd) },
		// With --update, upgrade in place; otherwise (no subcommand) show help.
		RunE: func(cmd *cobra.Command, _ []string) error {
			if doUpdate {
				return runUpdate(false, false)
			}
			return cmd.Help()
		},
	}
	root.PersistentFlags().StringVar(&addr, "addr", env("VAULT_ADDR", "https://vault.donkeywork.dev"), "vault address (https://host[:port] or host:port); default https://vault.donkeywork.dev")
	root.PersistentFlags().StringVar(&apiKey, "api-key", env("VAULT_API_KEY", ""), "access key for authentication (X-Api-Key)")
	root.Flags().BoolVar(&doUpdate, "update", false, "upgrade dwvault to the latest release in place (see `dwvault update`)")
	// Output discipline: STDOUT is reserved for the requested secret/token. Send all
	// Cobra-generated text (help, usage, --version) to STDERR; the secret commands write
	// to os.Stdout directly and are unaffected.
	root.SetOut(os.Stderr)

	// `credentials` is the canonical group; `creds` stays as a hidden alias so existing scripts and
	// agents that shell out keep working without surfacing the shorthand in help.
	creds := &cobra.Command{
		Use:     "credentials",
		Aliases: []string{"creds"},
		Short:   "Manage and retrieve API-key credentials",
		Long:    "Manage and retrieve API-key credentials.\n\nEvery credential has a kind that tags how the secret is used:\n\n" + kindHelp,
	}
	creds.AddCommand(cmdList(), cmdGet(), cmdHeader(), cmdShape(), cmdCreate(), cmdCredDelete())

	oauth := &cobra.Command{Use: "oauth", Short: "Retrieve OAuth access tokens"}
	oauth.AddCommand(cmdOAuthToken(), cmdOAuthList())

	keys := &cobra.Command{Use: "keys", Short: "Manage access keys (scoped auth credentials)"}
	keys.AddCommand(cmdKeysList(), cmdKeysCreate(), cmdKeysSetEnabled(true), cmdKeysSetEnabled(false), cmdKeysDelete())

	root.AddCommand(creds, oauth, keys, authCmd(), cmdSkill(), cmdUpdate(), cmdUpdateCheckHidden())

	if err := root.Execute(); err != nil {
		fail("%v", err)
	}
}

func cmdList() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List your credentials (name, description, base-url, kind) for discovery",
		Long: "List your credentials as a light discovery payload: name, a truncated description,\n" +
			"base URL, and kind. Pick one and run `dwvault credentials shape <name>` for\n" +
			"the full usage detail (header, prefix, username, docs).",
		RunE: func(_ *cobra.Command, _ []string) error {
			client, err := newClient()
			if err != nil {
				return err
			}
			ctx, cancel := reqCtx()
			defer cancel()
			resp, err := client.GetApiV1ApiKeysWithResponse(ctx)
			if err != nil {
				return err
			}
			if resp.JSON200 == nil {
				return apiError("list api keys", resp.Status(), resp.Body)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tDESCRIPTION\tBASE URL\tKIND")
			for _, k := range *resp.JSON200 {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
					k.Name, truncate(deref(k.Description), 60), deref(k.BaseUrl), string(k.Kind))
			}
			return w.Flush()
		},
	}
}

func cmdGet() *cobra.Command {
	return &cobra.Command{
		Use:   "get <name>",
		Short: "Print a stored secret to stdout (for shell substitution)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			client, err := newClient()
			if err != nil {
				return err
			}
			ctx, cancel := reqCtx()
			defer cancel()
			resp, err := client.GetApiV1ApiKeysNameRevealWithResponse(ctx, args[0])
			if err != nil {
				return err
			}
			if resp.JSON200 == nil {
				return apiError(fmt.Sprintf("reveal credential %q", args[0]), resp.Status(), resp.Body)
			}
			fmt.Println(resp.JSON200.Secret) // ONLY the secret to stdout
			return nil
		},
	}
}

func cmdShape() *cobra.Command {
	return &cobra.Command{
		Use:   "shape <name>",
		Short: "Print how to use the credential (kind, scheme, username, header, prefix, base url, docs)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			client, err := newClient()
			if err != nil {
				return err
			}
			ctx, cancel := reqCtx()
			defer cancel()
			resp, err := client.GetApiV1CredentialsNameWithResponse(ctx, args[0])
			if err != nil {
				return err
			}
			if resp.JSON200 == nil {
				return apiError(fmt.Sprintf("describe credential %q", args[0]), resp.Status(), resp.Body)
			}
			s := resp.JSON200
			out, _ := json.MarshalIndent(map[string]any{
				"kind":        string(s.Kind),
				"description": s.Description,
				"scheme":      s.Scheme,
				"username":    s.Username,
				"base_url":    s.BaseUrl,
				"header":      s.Header,
				"prefix":      s.Prefix,
				"docs_url":    s.DocsUrl,
			}, "", "  ")
			fmt.Println(string(out))
			return nil
		},
	}
}

func cmdHeader() *cobra.Command {
	return &cobra.Command{
		Use:   "header <name>",
		Short: "Print the ready Authorization header line (for curl -H), e.g. Basic base64(user:pass)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			client, err := newClient()
			if err != nil {
				return err
			}
			ctx, cancel := reqCtx()
			defer cancel()
			resp, err := client.GetApiV1ApiKeysNameRevealWithResponse(ctx, args[0])
			if err != nil {
				return err
			}
			if resp.JSON200 == nil {
				return apiError(fmt.Sprintf("reveal credential %q", args[0]), resp.Status(), resp.Body)
			}
			// Full "Name: value" line so it drops into `curl -H "$(dwvault creds header foo)"`.
			fmt.Printf("%s: %s\n", resp.JSON200.Header, resp.JSON200.HeaderValue)
			return nil
		},
	}
}

func cmdOAuthToken() *cobra.Command {
	var account string
	c := &cobra.Command{
		Use: "get <provider>",
		// `token` was the original verb; keep it as a hidden alias so existing scripts
		// and agent skills that shell out keep working.
		Aliases: []string{"token"},
		Short:   "Print a valid OAuth access token to stdout (auto-refreshed)",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			client, err := newClient()
			if err != nil {
				return err
			}
			ctx, cancel := reqCtx()
			defer cancel()
			params := &vaultapi.GetApiV1OauthProviderTokenParams{}
			if account != "" {
				params.Account = &account
			}
			resp, err := client.GetApiV1OauthProviderTokenWithResponse(ctx, args[0], params)
			if err != nil {
				return err
			}
			if resp.JSON200 == nil {
				// Not connected. A browser/device connect flow would start here.
				fmt.Fprintf(os.Stderr, "not connected to %s — no stored token (%s)\n", args[0], resp.Status())
				os.Exit(2)
			}
			fmt.Println(resp.JSON200.AccessToken) // ONLY the token to stdout
			return nil
		},
	}
	c.Flags().StringVar(&account, "account", "", "select among multiple connected accounts")
	return c
}

func cmdOAuthList() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List connected OAuth providers",
		RunE: func(_ *cobra.Command, _ []string) error {
			client, err := newClient()
			if err != nil {
				return err
			}
			ctx, cancel := reqCtx()
			defer cancel()
			resp, err := client.GetApiV1OauthTokensWithResponse(ctx)
			if err != nil {
				return err
			}
			if resp.JSON200 == nil {
				return apiError("list oauth tokens", resp.Status(), resp.Body)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "PROVIDER\tACCOUNT\tSTATUS\tSCOPES")
			for _, t := range *resp.JSON200 {
				fmt.Fprintf(w, "%s\t%s\tconnected\t%s\n", t.Provider, t.Account, strings.Join(t.Scopes, " "))
			}
			return w.Flush()
		},
	}
}

func cmdCreate() *cobra.Command {
	var secret, description, baseURL, docs, header, prefix, username, kind string
	c := &cobra.Command{
		Use:   "create <name>",
		Short: "Store a self-describing credential (set --kind for ssh/connection_string/etc.)",
		Long: "Store a self-describing credential. --kind tags how the secret is used (default\n" +
			"opaque); the vault returns it on discovery so an agent knows what it is:\n\n" + kindHelp,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if secret == "" {
				return fmt.Errorf("--secret is required")
			}
			// A bare --username with no explicit --kind is HTTP Basic — the historical default.
			if username != "" && !cmd.Flags().Changed("kind") {
				kind = "http_basic"
			}
			if !validKind(kind) {
				return fmt.Errorf("--kind %q is not one of: opaque, header_api_key, http_basic, username_password, ssh, connection_string", kind)
			}
			// --header/--prefix only apply to header_api_key; reject them on any other kind rather
			// than silently ignoring (the kind discriminator is the source of truth server-side).
			headerish := kind == "header_api_key"
			if !headerish && (cmd.Flags().Changed("header") || cmd.Flags().Changed("prefix")) {
				return fmt.Errorf("--header/--prefix only apply to --kind header_api_key")
			}

			client, err := newClient()
			if err != nil {
				return err
			}
			ctx, cancel := reqCtx()
			defer cancel()
			body := vaultapi.PostApiV1ApiKeysJSONRequestBody{
				Name:        args[0],
				Secret:      strPtr(secret),
				Description: strPtr(description),
				BaseUrl:     strPtr(baseURL),
				DocsUrl:     strPtr(docs),
				Username:    strPtr(username),
				Kind:        vaultapi.CredentialKind(kind),
			}
			if headerish {
				body.Header = strPtr(header)
				body.Prefix = strPtr(prefix)
			}
			resp, err := client.PostApiV1ApiKeysWithResponse(ctx, body)
			if err != nil {
				return err
			}
			if resp.JSON200 == nil {
				return apiError(fmt.Sprintf("create credential %q", args[0]), resp.Status(), resp.Body)
			}
			fmt.Fprintf(os.Stderr, "stored %s (%s) kind=%s\n", resp.JSON200.Name, resp.JSON200.Id, kind)
			return nil
		},
	}
	c.Flags().StringVar(&secret, "secret", "", "the API key value, or password with --username (required)")
	c.Flags().StringVar(&description, "description", "", "what this credential is for")
	c.Flags().StringVar(&baseURL, "base-url", "", "host / base URL where it's used")
	c.Flags().StringVar(&docs, "docs", "", "API documentation link")
	c.Flags().StringVar(&header, "header", "Authorization", "header name to send")
	c.Flags().StringVar(&prefix, "prefix", "", "optional value prefix, e.g. 'Bearer '")
	c.Flags().StringVar(&username, "username", "", "login username; bare --username defaults --kind to http_basic (also used by username_password/ssh)")
	c.Flags().StringVar(&kind, "kind", "opaque", "credential kind: opaque|header_api_key|http_basic|username_password|ssh|connection_string")
	return c
}

func cmdCredDelete() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a stored credential by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			client, err := newClient()
			if err != nil {
				return err
			}
			ctx, cancel := reqCtx()
			defer cancel()
			// The delete API is keyed by id; resolve the name to its id first.
			list, err := client.GetApiV1ApiKeysWithResponse(ctx)
			if err != nil {
				return err
			}
			if list.JSON200 == nil {
				return apiError("list api keys", list.Status(), list.Body)
			}
			var target *vaultapi.ApiKeyDto
			for i := range *list.JSON200 {
				if (*list.JSON200)[i].Name == args[0] {
					target = &(*list.JSON200)[i]
					break
				}
			}
			if target == nil {
				return fmt.Errorf("no credential named %q", args[0])
			}
			resp, err := client.DeleteApiV1ApiKeysIdWithResponse(ctx, target.Id)
			if err != nil {
				return err
			}
			if resp.StatusCode()/100 != 2 {
				return apiError(fmt.Sprintf("delete credential %q", args[0]), resp.Status(), resp.Body)
			}
			fmt.Fprintf(os.Stderr, "deleted %s\n", args[0])
			return nil
		},
	}
}

// kindHelp is the one-line-per-kind reference shared by `credentials --help`
// and `credentials create --help`.
const kindHelp = "  opaque (default)   — the secret is returned verbatim (HMAC secrets, DSNs, …).\n" +
	"  header_api_key     — sent as \"<header>: <prefix><secret>\" (--header/--prefix).\n" +
	"  http_basic         — Authorization: Basic base64(username:secret) (--username).\n" +
	"  username_password  — a username+password login NOT sent as Basic (ROPC, DSM, DB).\n" +
	"  ssh                — SSH login: --username + --base-url ssh://host:port.\n" +
	"  connection_string  — the whole DSN is the secret."

// validKind reports whether k is one of the supported credential kinds.
func validKind(k string) bool {
	switch k {
	case "opaque", "header_api_key", "http_basic", "username_password", "ssh", "connection_string":
		return true
	default:
		return false
	}
}

func cmdKeysList() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List your access keys (id, scopes, enabled state)",
		RunE: func(_ *cobra.Command, _ []string) error {
			client, err := newClient()
			if err != nil {
				return err
			}
			ctx, cancel := reqCtx()
			defer cancel()
			resp, err := client.GetApiV1AccessKeysWithResponse(ctx)
			if err != nil {
				return err
			}
			if resp.JSON200 == nil {
				return apiError("list access keys", resp.Status(), resp.Body)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tSCOPES\tENABLED\tPREFIX\tLAST USED")
			for _, k := range *resp.JSON200 {
				last := "-"
				if k.LastUsedAt != nil {
					last = k.LastUsedAt.Format(time.RFC3339)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%t\t%s…\t%s\n", k.Id, k.Name, strings.Join(k.Scopes, ","), k.Enabled, k.Prefix, last)
			}
			return w.Flush()
		},
	}
}

func cmdKeysCreate() *cobra.Command {
	var description string
	var scopes []string
	c := &cobra.Command{
		Use:   "create <name>",
		Short: "Mint an access key; the secret is printed once to stdout",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			client, err := newClient()
			if err != nil {
				return err
			}
			ctx, cancel := reqCtx()
			defer cancel()
			body := vaultapi.PostApiV1AccessKeysJSONRequestBody{
				Name:        args[0],
				Description: strPtr(description),
			}
			if len(scopes) > 0 {
				body.Scopes = &scopes
			}
			resp, err := client.PostApiV1AccessKeysWithResponse(ctx, body)
			if err != nil {
				return err
			}
			if resp.JSON200 == nil {
				return apiError(fmt.Sprintf("create access key %q", args[0]), resp.Status(), resp.Body)
			}
			// Metadata to stderr; ONLY the secret to stdout (safe for capture, shown once).
			fmt.Fprintf(os.Stderr, "created %s (%s) scopes=[%s]\n",
				resp.JSON200.Name, resp.JSON200.Id, strings.Join(resp.JSON200.Scopes, " "))
			fmt.Println(resp.JSON200.Secret)
			return nil
		},
	}
	c.Flags().StringVar(&description, "description", "", "what this key is for")
	c.Flags().StringArrayVar(&scopes, "scope", nil, "grant a scope (repeatable): vault:read|vault:readwrite|vault:audit")
	return c
}

func cmdKeysSetEnabled(enabled bool) *cobra.Command {
	use, short := "disable <id>", "Disable an access key"
	if enabled {
		use, short = "enable <id>", "Enable an access key"
	}
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid access key id %q: %w", args[0], err)
			}
			client, err := newClient()
			if err != nil {
				return err
			}
			ctx, cancel := reqCtx()
			defer cancel()
			resp, err := client.PatchApiV1AccessKeysIdWithResponse(ctx, id,
				vaultapi.PatchApiV1AccessKeysIdJSONRequestBody{Enabled: enabled})
			if err != nil {
				return err
			}
			if resp.JSON200 == nil {
				return apiError(fmt.Sprintf("update access key %q", args[0]), resp.Status(), resp.Body)
			}
			fmt.Fprintf(os.Stderr, "%s is now enabled=%t\n", resp.JSON200.Id, resp.JSON200.Enabled)
			return nil
		},
	}
}

func cmdKeysDelete() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete an access key",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid access key id %q: %w", args[0], err)
			}
			client, err := newClient()
			if err != nil {
				return err
			}
			ctx, cancel := reqCtx()
			defer cancel()
			resp, err := client.DeleteApiV1AccessKeysIdWithResponse(ctx, id)
			if err != nil {
				return err
			}
			if resp.StatusCode()/100 != 2 {
				return apiError(fmt.Sprintf("delete access key %q", args[0]), resp.Status(), resp.Body)
			}
			fmt.Fprintf(os.Stderr, "deleted %s\n", args[0])
			return nil
		},
	}
}

// truncate shortens s to at most n runes, appending an ellipsis when it was cut, so the
// discovery table stays scannable regardless of description length.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// strPtr returns a pointer to s, or nil when s is empty (so omitted flags stay unset).
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// fmtTime formats an optional timestamp for table output.
func fmtTime(t *time.Time) string {
	if t == nil {
		return "no expiry"
	}
	return t.Format(time.RFC3339)
}
