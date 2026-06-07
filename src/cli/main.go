// dwcred — DonkeyWork Vault credential CLI.
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
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	pb "donkeywork.dev/vault-cli/internal/vaultpb"

	"github.com/spf13/cobra"
)

var (
	addr     string
	userID   string
	tenantID string
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "dwcred: "+format+"\n", a...)
	os.Exit(1)
}

// dial opens a plaintext (h2c) connection and returns a context carrying identity metadata.
func dial() (*grpc.ClientConn, context.Context, context.CancelFunc) {
	if userID == "" {
		fail("no user id; set VAULT_USER_ID or --user")
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fail("connect %s: %v", addr, err)
	}
	pairs := []string{"x-user-id", userID}
	if tenantID != "" {
		pairs = append(pairs, "x-tenant-id", tenantID)
	}
	ctx, cancel := context.WithTimeout(
		metadata.NewOutgoingContext(context.Background(), metadata.Pairs(pairs...)),
		20*time.Second,
	)
	return conn, ctx, cancel
}

func main() {
	root := &cobra.Command{
		Use:           "dwcred",
		Short:         "DonkeyWork Vault credential CLI",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&addr, "addr", env("VAULT_ADDR", "localhost:8080"), "vault gRPC address")
	root.PersistentFlags().StringVar(&userID, "user", env("VAULT_USER_ID", ""), "caller user id (x-user-id)")
	root.PersistentFlags().StringVar(&tenantID, "tenant", env("VAULT_TENANT_ID", ""), "caller tenant id (x-tenant-id)")

	creds := &cobra.Command{Use: "creds", Short: "Manage and retrieve API-key credentials"}
	creds.AddCommand(cmdList(), cmdGet(), cmdShape(), cmdCreate())
	root.AddCommand(creds, cmdProviders())

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
		Short: "List your stored API keys",
		RunE: func(_ *cobra.Command, _ []string) error {
			conn, ctx, cancel := dial()
			defer conn.Close()
			defer cancel()
			resp, err := pb.NewApiKeysClient(conn).List(ctx, &pb.ListApiKeysRequest{})
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "PROVIDER\tNAME\tID\tCREATED")
			for _, k := range resp.Items {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", k.Provider, k.Name, k.Id, k.CreatedAt)
			}
			return w.Flush()
		},
	}
}

func cmdGet() *cobra.Command {
	var name string
	c := &cobra.Command{
		Use:   "get <provider>",
		Short: "Print a stored secret to stdout (for shell substitution)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			conn, ctx, cancel := dial()
			defer conn.Close()
			defer cancel()
			resp, err := pb.NewCredentialStoreClient(conn).GetApiKey(ctx, &pb.GetApiKeyRequest{Provider: args[0], Name: name})
			if err != nil {
				return err
			}
			if !resp.Found {
				fail("no credential for provider %q", args[0])
			}
			fmt.Println(resp.Secret) // ONLY the secret to stdout
			return nil
		},
	}
	c.Flags().StringVar(&name, "name", "", "select among multiple stored keys")
	return c
}

func cmdShape() *cobra.Command {
	var name string
	c := &cobra.Command{
		Use:   "shape <provider>",
		Short: "Print how to present the credential (base url, header, prefix, static headers)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			conn, ctx, cancel := dial()
			defer conn.Close()
			defer cancel()
			resp, err := pb.NewCredentialStoreClient(conn).DescribeCredential(ctx, &pb.DescribeCredentialRequest{Provider: args[0], Name: name})
			if err != nil {
				return err
			}
			if !resp.Found || resp.Shape == nil {
				fail("no shape for provider %q", args[0])
			}
			out, _ := json.MarshalIndent(map[string]any{
				"base_url":       resp.Shape.BaseUrl,
				"header":         resp.Shape.Header,
				"prefix":         resp.Shape.Prefix,
				"static_headers": resp.Shape.StaticHeaders,
			}, "", "  ")
			fmt.Println(string(out))
			return nil
		},
	}
	c.Flags().StringVar(&name, "name", "", "select among multiple stored keys")
	return c
}

func cmdCreate() *cobra.Command {
	var name string
	var fields []string
	c := &cobra.Command{
		Use:   "create <provider>",
		Short: "Store an API key (--field name=value, repeatable)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			fm := map[string]string{}
			for _, f := range fields {
				k, v, ok := strings.Cut(f, "=")
				if !ok {
					fail("bad --field %q (want name=value)", f)
				}
				fm[k] = v
			}
			conn, ctx, cancel := dial()
			defer conn.Close()
			defer cancel()
			item, err := pb.NewApiKeysClient(conn).Create(ctx, &pb.CreateApiKeyRequest{Provider: args[0], Name: name, Fields: fm})
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "stored %s/%s (%s)\n", item.Provider, item.Name, item.Id)
			return nil
		},
	}
	c.Flags().StringVar(&name, "name", "default", "credential name")
	c.Flags().StringArrayVar(&fields, "field", nil, "field as name=value (repeatable)")
	return c
}
