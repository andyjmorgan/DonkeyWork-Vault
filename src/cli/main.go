// dwvault — DonkeyWork Vault credential CLI.
//
// Talks to the Vault HTTP API. Machine auth is a dwvault API key (dwv_…) sent as
// the X-Api-Key header; the key is resolved from --api-key / VAULT_API_KEY, the OS
// keyring, or the 0600 file written by `dwvault auth login`.
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
	userID   string
	tenantID string
	apiKey   string
	useTLS   bool
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
	}
	root.PersistentFlags().StringVar(&addr, "addr", env("VAULT_ADDR", "localhost:8080"), "vault address (host:port or https://host:port)")
	root.PersistentFlags().StringVar(&userID, "user", env("VAULT_USER_ID", ""), "caller user id (on-prem only)")
	root.PersistentFlags().StringVar(&tenantID, "tenant", env("VAULT_TENANT_ID", ""), "caller tenant id")
	root.PersistentFlags().StringVar(&apiKey, "api-key", env("VAULT_API_KEY", ""), "access key for authentication (X-Api-Key)")
	root.PersistentFlags().BoolVar(&useTLS, "tls", env("VAULT_TLS", "") != "", "use TLS (implied by an https://host address)")

	creds := &cobra.Command{Use: "creds", Short: "Manage and retrieve API-key credentials"}
	creds.AddCommand(cmdList(), cmdGet(), cmdHeader(), cmdShape(), cmdCreate())

	oauth := &cobra.Command{Use: "oauth", Short: "Retrieve OAuth access tokens"}
	oauth.AddCommand(cmdOAuthToken(), cmdOAuthList())

	keys := &cobra.Command{Use: "keys", Short: "Manage access keys (scoped auth credentials)"}
	keys.AddCommand(cmdKeysList(), cmdKeysCreate(), cmdKeysSetEnabled(true), cmdKeysSetEnabled(false), cmdKeysDelete())

	root.AddCommand(creds, oauth, keys, cmdProviders(), authCmd())

	if err := root.Execute(); err != nil {
		fail("%v", err)
	}
}

func cmdProviders() *cobra.Command {
	return &cobra.Command{
		Use:   "providers",
		Short: "List the API-key provider catalog",
		RunE: func(_ *cobra.Command, _ []string) error {
			client, err := newClient()
			if err != nil {
				return err
			}
			ctx, cancel := reqCtx()
			defer cancel()
			resp, err := client.GetApiV1ProvidersWithResponse(ctx)
			if err != nil {
				return err
			}
			if resp.JSON200 == nil {
				return apiError("list providers", resp.Status(), resp.Body)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "KEY\tNAME\tHEADER\tPREFIX")
			for _, p := range *resp.JSON200 {
				fmt.Fprintf(w, "%s\t%s\t%s\t%q\n", p.Key, p.Name, p.Header, p.Prefix)
			}
			return w.Flush()
		},
	}
}

func cmdList() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List your API keys with how to use each (header/prefix/base-url/docs)",
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
			fmt.Fprintln(w, "NAME\tDESCRIPTION\tHEADER\tPREFIX\tBASE URL\tDOCS")
			for _, k := range *resp.JSON200 {
				fmt.Fprintf(w, "%s\t%s\t%s\t%q\t%s\t%s\n",
					k.Name, deref(k.Description), deref(k.Header), deref(k.Prefix), deref(k.BaseUrl), deref(k.DocsUrl))
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
		Short: "Print how to use the credential (scheme, username, header, prefix, base url, docs)",
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
		Use:   "token <provider>",
		Short: "Print a valid OAuth access token to stdout (auto-refreshed)",
		Args:  cobra.ExactArgs(1),
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
			fmt.Fprintln(w, "PROVIDER\tACCOUNT\tEXPIRES\tSCOPES")
			for _, t := range *resp.JSON200 {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", t.Provider, t.Account, fmtTime(t.ExpiresAt), strings.Join(t.Scopes, " "))
			}
			return w.Flush()
		},
	}
}

func cmdCreate() *cobra.Command {
	var secret, description, baseURL, docs, header, prefix, username string
	c := &cobra.Command{
		Use:   "create <name>",
		Short: "Store a self-describing API key (set --username for HTTP Basic auth)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
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
				Header:      strPtr(header),
				Prefix:      strPtr(prefix),
				Username:    strPtr(username),
			}
			resp, err := client.PostApiV1ApiKeysWithResponse(ctx, body)
			if err != nil {
				return err
			}
			if resp.JSON200 == nil {
				return apiError(fmt.Sprintf("create credential %q", args[0]), resp.Status(), resp.Body)
			}
			fmt.Fprintf(os.Stderr, "stored %s (%s)\n", resp.JSON200.Name, resp.JSON200.Id)
			return nil
		},
	}
	c.Flags().StringVar(&secret, "secret", "", "the API key value, or password with --username (required)")
	c.Flags().StringVar(&description, "description", "", "what this credential is for")
	c.Flags().StringVar(&baseURL, "base-url", "", "host / base URL where it's used")
	c.Flags().StringVar(&docs, "docs", "", "API documentation link")
	c.Flags().StringVar(&header, "header", "Authorization", "header name to send")
	c.Flags().StringVar(&prefix, "prefix", "", "optional value prefix, e.g. 'Bearer '")
	c.Flags().StringVar(&username, "username", "", "username ⇒ HTTP Basic auth (secret is the password)")
	return c
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
		return "-"
	}
	return t.Format(time.RFC3339)
}
