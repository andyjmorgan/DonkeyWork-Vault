package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"donkeywork.dev/vault-cli/internal/config"
	"donkeywork.dev/vault-cli/internal/credstore"
	"donkeywork.dev/vault-cli/internal/restclient"
)

// httpBaseURL derives the REST base URL (and the credstore host key) from --addr.
// The scheme is the sole signal: an http(s):// addr is used verbatim; a bare host[:port]
// with no scheme defaults to plaintext http:// (give an https:// addr, or rely on the
// default https://vault.donkeywork.dev, for TLS).
func httpBaseURL() string {
	a := strings.TrimRight(addr, "/")
	switch {
	case strings.HasPrefix(a, "http://"), strings.HasPrefix(a, "https://"):
		return a
	default:
		return "http://" + a
	}
}

func authCmd() *cobra.Command {
	c := &cobra.Command{Use: "auth", Short: "Manage the stored API key for a vault host"}
	c.AddCommand(cmdAuthLogin(), cmdAuthStatus(), cmdAuthLogout())
	return c
}

func cmdAuthLogin() *cobra.Command {
	var force bool
	c := &cobra.Command{
		Use:   "login",
		Short: "Store an API key for the vault host (prompted, validated against /me)",
		Long: "Store a pre-minted dwvault API key (dwv_…) for the host given by --addr.\n" +
			"Mint the key in the portal after logging in; this command never mints one.\n" +
			"The key is validated against /api/v1/me, then saved to the OS keyring (or a\n" +
			"0600 file when no keyring is available).",
		RunE: func(_ *cobra.Command, _ []string) error {
			base := httpBaseURL()

			// Env key wins at runtime and must stay ephemeral — validate, never store.
			if v := os.Getenv("VAULT_API_KEY"); v != "" {
				me, err := restclient.FetchMe(base, v)
				if err != nil {
					return fmt.Errorf("VAULT_API_KEY is set but invalid for %s: %w", base, err)
				}
				fmt.Fprintf(os.Stderr,
					"VAULT_API_KEY is set and valid for %s (%s); it takes precedence and was not stored.\n",
					base, identity(me))
				return nil
			}

			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if _, exists := cfg.Hosts[base]; exists && !force {
				return fmt.Errorf("already logged in to %s; pass --force to replace", base)
			}

			key, err := promptSecret("Paste a dwvault API key (dwv_…): ")
			if err != nil {
				return err
			}
			key = strings.TrimSpace(key)
			if key == "" {
				return fmt.Errorf("no key entered")
			}

			me, err := restclient.FetchMe(base, key)
			if err != nil {
				return fmt.Errorf("key not accepted by %s: %w", base, err)
			}

			store, err := credstore.Store(base, key)
			if err != nil {
				return err
			}
			cfg.Hosts[base] = config.Host{Account: identity(me), Store: store}
			if err := config.Save(cfg); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "logged in to %s as %s (secret in %s)\n", base, identity(me), store)
			return nil
		},
	}
	c.Flags().BoolVar(&force, "force", false, "replace an existing stored credential")
	return c
}

func cmdAuthStatus() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the active credential source for the vault host",
		RunE: func(_ *cobra.Command, _ []string) error {
			base := httpBaseURL()
			key, src, err := credstore.Resolve(base)
			if err != nil {
				fmt.Fprintf(os.Stderr,
					"not logged in to %s — set VAULT_API_KEY or run `dwvault auth login`\n", base)
				os.Exit(1)
			}
			me, err := restclient.FetchMe(base, key)
			if err != nil {
				return fmt.Errorf("the %s credential for %s failed validation: %w", src, base, err)
			}
			fmt.Fprintf(os.Stderr, "host:    %s\nsource:  %s\naccount: %s\n", base, src, identity(me))
			return nil
		},
	}
}

func cmdAuthLogout() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove the stored credential for the vault host",
		RunE: func(_ *cobra.Command, _ []string) error {
			base := httpBaseURL()
			if err := credstore.Delete(base); err != nil {
				return err
			}
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			delete(cfg.Hosts, base)
			if err := config.Save(cfg); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "logged out of %s\n", base)
			return nil
		},
	}
}

func identity(m *restclient.Me) string {
	switch {
	case m == nil:
		return "unknown"
	case m.Email != "":
		return m.Email
	case m.Name != "":
		return m.Name
	case m.UserID != "":
		return m.UserID
	default:
		return "unknown"
	}
}

// promptSecret reads a secret from the terminal without echo. When stdin is not a
// TTY it falls back to a plain read, so `printf %s "$key" | dwvault auth login` works.
func promptSecret(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}
