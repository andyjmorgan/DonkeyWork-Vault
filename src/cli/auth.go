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
	"donkeywork.dev/vault-cli/internal/oauthdevice"
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
	c := &cobra.Command{Use: "auth", Short: "Manage the stored login for a vault host"}
	c.AddCommand(cmdAuthLogin(), cmdAuthStatus(), cmdAuthLogout())
	return c
}

func cmdAuthLogin() *cobra.Command {
	var force, oauthMode, apiKeyMode bool
	c := &cobra.Command{
		Use:   "login",
		Short: "Sign in to the vault host (OAuth device login by default)",
		Long: "Sign in to the host given by --addr. Interactive terminals show a small selector and\n" +
			"default to OAuth device login. Scripts must pass --oauth or --api-key explicitly.\n" +
			"OAuth credentials and API keys are saved to the OS keyring, or a 0600 file when no\n" +
			"keyring is available.",
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

			if oauthMode && apiKeyMode {
				return fmt.Errorf("--oauth and --api-key are mutually exclusive")
			}
			var mode string
			switch {
			case oauthMode:
				mode = "oauth"
			case apiKeyMode:
				mode = "api_key"
			case term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd())):
				var err error
				mode, err = authModeMenu()
				if err != nil {
					return err
				}
			default:
				return fmt.Errorf("non-interactive login requires --oauth or --api-key")
			}
			if mode == "api_key" {
				return loginAPIKey(base, cfg)
			}
			return loginOAuth(base, cfg)
		},
	}
	c.Flags().BoolVar(&force, "force", false, "replace an existing stored credential")
	c.Flags().BoolVar(&oauthMode, "oauth", false, "use OAuth device login without showing the selector")
	c.Flags().BoolVar(&apiKeyMode, "api-key", false, "paste a dwvault API key without showing the selector")
	return c
}

func cmdAuthStatus() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the active credential source for the vault host",
		RunE: func(_ *cobra.Command, _ []string) error {
			base := httpBaseURL()
			c, src, err := credstore.ResolveCredential(base)
			if err != nil {
				fmt.Fprintf(os.Stderr,
					"not logged in to %s — set VAULT_API_KEY or run `dwvault auth login`\n", base)
				os.Exit(1)
			}
			switch c.Type {
			case credstore.TypeAPIKey:
				me, err := restclient.FetchMe(base, c.Secret)
				if err != nil {
					return fmt.Errorf("the %s credential for %s failed validation: %w", src, base, err)
				}
				fmt.Fprintf(os.Stderr, "host:    %s\nauth:    api_key\nsource:  %s\naccount: %s\n", base, src, identity(me))
			case credstore.TypeOAuth:
				token, err := oauthAccessToken(base, c, src)
				if err != nil {
					return fmt.Errorf("the %s OAuth credential for %s failed refresh: %w", src, base, err)
				}
				me, err := restclient.FetchMeBearer(base, token)
				if err != nil {
					return fmt.Errorf("the %s OAuth credential for %s failed validation: %w", src, base, err)
				}
				fmt.Fprintf(os.Stderr, "host:    %s\nauth:    oauth\nsource:  %s\naccount: %s\nissuer:  %s\n", base, src, identity(me), c.Issuer)
			default:
				return fmt.Errorf("unsupported credential type %q", c.Type)
			}
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

func loginAPIKey(base string, cfg *config.Config) error {
	key, err := promptSecret("Paste a dwvault API key (dwv_...): ")
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
	cfg.Hosts[base] = config.Host{Account: identity(me), Store: store, Auth: config.AuthAPIKey}
	if err := config.Save(cfg); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "logged in to %s as %s (auth api_key, secret in %s)\n", base, identity(me), store)
	return nil
}

func loginOAuth(base string, cfg *config.Config) error {
	app, err := restclient.FetchConfig(base)
	if err != nil {
		return err
	}
	if !app.AuthEnabled || app.Authority == "" {
		return fmt.Errorf("%s does not advertise OIDC auth", base)
	}
	clientID := app.CliClientID
	if clientID == "" {
		clientID = "donkeywork-vault-cli"
	}
	scopes := app.CliScopes
	if scopes == "" {
		scopes = "openid profile email offline_access"
	}
	d, err := oauthdevice.Discover(app.Authority)
	if err != nil {
		return err
	}
	start, err := oauthdevice.Start(d, clientID, scopes)
	if err != nil {
		return err
	}
	url := start.VerificationURIComplete
	if url == "" {
		url = start.VerificationURI
	}
	fmt.Fprintf(os.Stderr, "Open this URL to authorize dwvault:\n\n%s\n\n", url)
	if start.VerificationURIComplete == "" {
		fmt.Fprintf(os.Stderr, "Code: %s\n\n", start.UserCode)
	}
	fmt.Fprintln(os.Stderr, "Waiting for authorization...")
	tok, err := oauthdevice.Poll(d, clientID, start, nil)
	if err != nil {
		return err
	}
	cred := &credstore.Credential{
		Type:         credstore.TypeOAuth,
		Issuer:       d.Issuer,
		ClientID:     clientID,
		Scopes:       scopes,
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
	}
	updateOAuthCredential(cred, tok)
	claims := oauthdevice.DecodeClaims(tok.AccessToken)
	cred.Account = firstNonEmpty(claims.Email, claims.PreferredUsername, claims.Subject)
	store, err := credstore.StoreCredential(base, cred)
	if err != nil {
		return err
	}
	cfg.Hosts[base] = config.Host{Account: cred.Account, Store: store, Auth: config.AuthOAuth}
	if err := config.Save(cfg); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "logged in to %s as %s (auth oauth, secret in %s)\n", base, cred.Account, store)
	return nil
}

func authModeMenu() (string, error) {
	fmt.Fprintln(os.Stderr, "How do you want to sign in?")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  1. OAuth device login (recommended)")
	fmt.Fprintln(os.Stderr, "  2. Paste API key")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprint(os.Stderr, "Choose [1]: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	switch strings.TrimSpace(line) {
	case "", "1":
		return "oauth", nil
	case "2":
		return "api_key", nil
	default:
		return "", fmt.Errorf("invalid selection")
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return "unknown"
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
