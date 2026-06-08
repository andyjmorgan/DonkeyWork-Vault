// dwvault — DonkeyWork Vault credential CLI.
//
// Talks directly to the Vault gRPC service. Identity is supplied via env/flags
// (VAULT_USER_ID / VAULT_TENANT_ID) and sent as x-user-id / x-tenant-id metadata.
//
// Output discipline: the requested secret/token goes to STDOUT only (no decoration,
// safe for shell substitution). All logs, prompts and errors go to STDERR. A miss or
// error exits non-zero.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	pb "donkeywork.dev/vault-cli/internal/vaultpb"

	"github.com/spf13/cobra"
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

// dial opens a connection and returns a context carrying the caller's auth metadata.
//
// Transport: TLS when --tls / VAULT_TLS is set or the address uses a grpcs://|https:// scheme
// (for an internet-facing vault behind a TLS edge); plaintext h2c otherwise (local/in-cluster).
//
// Identity: an API key (x-api-key) is preferred; falling back to a bare user id (x-user-id) which
// the vault only honours when its on-prem AllowUnauthenticatedUserId flag is set.
func dial() (*grpc.ClientConn, context.Context, context.CancelFunc) {
	target, secure := parseTarget(addr, useTLS)

	var creds credentials.TransportCredentials
	if secure {
		creds = credentials.NewTLS(&tls.Config{})
	} else {
		creds = insecure.NewCredentials()
	}
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(creds))
	if err != nil {
		fail("connect %s: %v", target, err)
	}

	var pairs []string
	switch {
	case apiKey != "":
		pairs = []string{"x-api-key", apiKey}
	case userID != "":
		pairs = []string{"x-user-id", userID}
		if tenantID != "" {
			pairs = append(pairs, "x-tenant-id", tenantID)
		}
	default:
		fail("no credentials; set VAULT_API_KEY (mint one with `dwvault keys create`) or VAULT_USER_ID for on-prem")
	}
	ctx, cancel := context.WithTimeout(
		metadata.NewOutgoingContext(context.Background(), metadata.Pairs(pairs...)),
		20*time.Second,
	)
	return conn, ctx, cancel
}

// parseTarget strips a scheme from addr and decides the transport. An explicit grpcs://|https://
// (or --tls) selects TLS; grpc://|http:// or a bare host:port stays plaintext.
func parseTarget(addr string, tlsFlag bool) (target string, secure bool) {
	secure = tlsFlag
	switch {
	case strings.HasPrefix(addr, "grpcs://"):
		return addr[len("grpcs://"):], true
	case strings.HasPrefix(addr, "https://"):
		return addr[len("https://"):], true
	case strings.HasPrefix(addr, "grpc://"):
		return addr[len("grpc://"):], false
	case strings.HasPrefix(addr, "http://"):
		return addr[len("http://"):], false
	}
	return addr, secure
}

func main() {
	root := &cobra.Command{
		Use:           "dwvault",
		Short:         "DonkeyWork Vault credential CLI",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&addr, "addr", env("VAULT_ADDR", "localhost:8080"), "vault gRPC address (host:port or grpcs://host:port)")
	root.PersistentFlags().StringVar(&userID, "user", env("VAULT_USER_ID", ""), "caller user id (x-user-id; on-prem only)")
	root.PersistentFlags().StringVar(&tenantID, "tenant", env("VAULT_TENANT_ID", ""), "caller tenant id (x-tenant-id)")
	root.PersistentFlags().StringVar(&apiKey, "api-key", env("VAULT_API_KEY", ""), "access key for authentication (x-api-key)")
	root.PersistentFlags().BoolVar(&useTLS, "tls", env("VAULT_TLS", "") != "", "use TLS (implied by a grpcs://host address)")

	creds := &cobra.Command{Use: "creds", Short: "Manage and retrieve API-key credentials"}
	creds.AddCommand(cmdList(), cmdGet(), cmdShape(), cmdCreate())

	oauth := &cobra.Command{Use: "oauth", Short: "Retrieve OAuth access tokens"}
	oauth.AddCommand(cmdOAuthToken(), cmdOAuthList())

	keys := &cobra.Command{Use: "keys", Short: "Manage access keys (scoped auth credentials)"}
	keys.AddCommand(cmdKeysList(), cmdKeysCreate(), cmdKeysSetEnabled(true), cmdKeysSetEnabled(false), cmdKeysDelete())

	root.AddCommand(creds, oauth, keys, cmdProviders())

	if err := root.Execute(); err != nil {
		fail("%v", err)
	}
}

func cmdProviders() *cobra.Command {
	return &cobra.Command{
		Use:   "providers",
		Short: "List the API-key provider catalog",
		RunE: func(_ *cobra.Command, _ []string) error {
			conn, ctx, cancel := dial()
			defer conn.Close()
			defer cancel()
			resp, err := pb.NewApiKeyCatalogClient(conn).ListProviders(ctx, &pb.ListProvidersRequest{})
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "KEY\tNAME\tHEADER\tPREFIX")
			for _, p := range resp.Providers {
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
			conn, ctx, cancel := dial()
			defer conn.Close()
			defer cancel()
			resp, err := pb.NewApiKeysClient(conn).List(ctx, &pb.ListApiKeysRequest{})
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tDESCRIPTION\tHEADER\tPREFIX\tBASE URL\tDOCS")
			for _, k := range resp.Items {
				fmt.Fprintf(w, "%s\t%s\t%s\t%q\t%s\t%s\n", k.Name, k.Description, k.Header, k.Prefix, k.BaseUrl, k.DocsUrl)
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
			conn, ctx, cancel := dial()
			defer conn.Close()
			defer cancel()
			resp, err := pb.NewCredentialStoreClient(conn).GetApiKey(ctx, &pb.GetApiKeyRequest{Name: args[0]})
			if err != nil {
				return err
			}
			if !resp.Found {
				fail("no credential named %q", args[0])
			}
			fmt.Println(resp.Secret) // ONLY the secret to stdout
			return nil
		},
	}
}

func cmdShape() *cobra.Command {
	return &cobra.Command{
		Use:   "shape <name>",
		Short: "Print how to use the credential (description, base url, header, prefix, docs)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			conn, ctx, cancel := dial()
			defer conn.Close()
			defer cancel()
			resp, err := pb.NewCredentialStoreClient(conn).DescribeCredential(ctx, &pb.DescribeCredentialRequest{Name: args[0]})
			if err != nil {
				return err
			}
			if !resp.Found {
				fail("no credential named %q", args[0])
			}
			out, _ := json.MarshalIndent(map[string]any{
				"description": resp.Description,
				"base_url":    resp.BaseUrl,
				"header":      resp.Header,
				"prefix":      resp.Prefix,
				"docs_url":    resp.DocsUrl,
			}, "", "  ")
			fmt.Println(string(out))
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
			conn, ctx, cancel := dial()
			defer conn.Close()
			defer cancel()
			resp, err := pb.NewCredentialStoreClient(conn).GetOAuthAccessToken(ctx, &pb.GetOAuthAccessTokenRequest{Provider: args[0], Account: account})
			if err != nil {
				return err
			}
			if !resp.Found {
				// Not connected. A browser/device connect flow would start here.
				fmt.Fprintf(os.Stderr, "not connected to %s — no stored token\n", args[0])
				os.Exit(2)
			}
			fmt.Println(resp.AccessToken) // ONLY the token to stdout
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
			conn, ctx, cancel := dial()
			defer conn.Close()
			defer cancel()
			resp, err := pb.NewOAuthTokensClient(conn).List(ctx, &pb.ListOAuthTokensRequest{})
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "PROVIDER\tACCOUNT\tEXPIRES\tSCOPES")
			for _, t := range resp.Items {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", t.Provider, t.Account, t.ExpiresAt, strings.Join(t.Scopes, " "))
			}
			return w.Flush()
		},
	}
}

func cmdCreate() *cobra.Command {
	var secret, description, baseURL, docs, header, prefix string
	c := &cobra.Command{
		Use:   "create <name>",
		Short: "Store a self-describing API key",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			conn, ctx, cancel := dial()
			defer conn.Close()
			defer cancel()
			item, err := pb.NewApiKeysClient(conn).Create(ctx, &pb.CreateApiKeyRequest{
				Name: args[0], Secret: secret, Description: description,
				BaseUrl: baseURL, DocsUrl: docs, Header: header, Prefix: prefix,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "stored %s (%s)\n", item.Name, item.Id)
			return nil
		},
	}
	c.Flags().StringVar(&secret, "secret", "", "the API key value (required)")
	c.Flags().StringVar(&description, "description", "", "what this credential is for")
	c.Flags().StringVar(&baseURL, "base-url", "", "host / base URL where it's used")
	c.Flags().StringVar(&docs, "docs", "", "API documentation link")
	c.Flags().StringVar(&header, "header", "Authorization", "header name to send")
	c.Flags().StringVar(&prefix, "prefix", "", "optional value prefix, e.g. 'Bearer '")
	return c
}

func cmdKeysList() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List your access keys (id, scopes, enabled state)",
		RunE: func(_ *cobra.Command, _ []string) error {
			conn, ctx, cancel := dial()
			defer conn.Close()
			defer cancel()
			resp, err := pb.NewAccessKeysClient(conn).List(ctx, &pb.Empty{})
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tSCOPES\tENABLED\tPREFIX\tLAST USED")
			for _, k := range resp.Items {
				last := k.LastUsedAt
				if last == "" {
					last = "-"
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
			conn, ctx, cancel := dial()
			defer conn.Close()
			defer cancel()
			resp, err := pb.NewAccessKeysClient(conn).Create(ctx, &pb.CreateAccessKeyRequest{
				Name: args[0], Description: description, Scopes: scopes,
			})
			if err != nil {
				return err
			}
			// Metadata to stderr; ONLY the secret to stdout (safe for capture, shown once).
			fmt.Fprintf(os.Stderr, "created %s (%s) scopes=[%s]\n", resp.Item.Name, resp.Item.Id, strings.Join(resp.Item.Scopes, " "))
			fmt.Println(resp.Secret)
			return nil
		},
	}
	c.Flags().StringVar(&description, "description", "", "what this key is for")
	c.Flags().StringArrayVar(&scopes, "scope", nil, "grant a scope (repeatable): frontend:read|frontend:readwrite|vault:read|vault:readwrite")
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
			conn, ctx, cancel := dial()
			defer conn.Close()
			defer cancel()
			item, err := pb.NewAccessKeysClient(conn).SetEnabled(ctx, &pb.SetAccessKeyEnabledRequest{Id: args[0], Enabled: enabled})
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "%s is now enabled=%t\n", item.Name, item.Enabled)
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
			conn, ctx, cancel := dial()
			defer conn.Close()
			defer cancel()
			resp, err := pb.NewAccessKeysClient(conn).Delete(ctx, &pb.DeleteByIdRequest{Id: args[0]})
			if err != nil {
				return err
			}
			if !resp.Deleted {
				fail("no access key with id %q", args[0])
			}
			fmt.Fprintf(os.Stderr, "deleted %s\n", args[0])
			return nil
		},
	}
}
