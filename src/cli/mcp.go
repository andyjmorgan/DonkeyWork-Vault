package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var mcpOAuthCallbackPorts = []int{8000, 8080, 8888, 9000}

var (
	mcpOAuthBrowserOpen = openBrowser
	mcpOAuthTimeout     = 5 * time.Minute
)

func mcpCmd() *cobra.Command {
	c := &cobra.Command{Use: "mcp", Short: "Manage MCP gateway connections"}
	oauth := &cobra.Command{Use: "oauth", Short: "Authorize MCP upstreams"}
	oauth.AddCommand(cmdMCPOAuthConnect())
	c.AddCommand(oauth)
	return c
}

func cmdMCPOAuthConnect() *cobra.Command {
	return &cobra.Command{
		Use:   "connect <connection-id>",
		Short: "Authorize an MCP upstream using a local OAuth callback",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			connectionID, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid connection ID: %w", err)
			}
			return connectMCPOAuth(connectionID)
		},
	}
}

func connectMCPOAuth(connectionID uuid.UUID) error {
	listener, redirectURI, err := listenMCPOAuthCallback()
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()

	authorizeURL, err := beginMCPOAuth(connectionID, redirectURI)
	if err != nil {
		return err
	}
	parsed, err := url.Parse(authorizeURL)
	if err != nil || parsed.Query().Get("state") == "" {
		return fmt.Errorf("vault returned an invalid MCP OAuth authorization URL")
	}
	wantState := parsed.Query().Get("state")

	result := make(chan error, 1)
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second}
	server.Handler = mcpOAuthCallbackHandler(httpBaseURL(), wantState, result)
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && serveErr != http.ErrServerClosed {
			select {
			case result <- serveErr:
			default:
			}
		}
	}()
	defer func() { _ = server.Close() }()

	fmt.Fprintf(os.Stderr, "Open this URL to authorize the MCP connection:\n%s\n", authorizeURL)
	if err := mcpOAuthBrowserOpen(authorizeURL); err != nil {
		fmt.Fprintln(os.Stderr, "Could not open a browser automatically; open the URL above manually.")
	}
	select {
	case err := <-result:
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "MCP OAuth authorization completed; tokens are stored in Vault.")
		return nil
	case <-time.After(mcpOAuthTimeout):
		return fmt.Errorf("MCP OAuth authorization timed out")
	}
}

func listenMCPOAuthCallback() (net.Listener, string, error) {
	for _, port := range mcpOAuthCallbackPorts {
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			return listener, fmt.Sprintf("http://127.0.0.1:%d/oauth/callback", port), nil
		}
	}
	return nil, "", fmt.Errorf("could not bind a Datadog OAuth callback port (%v)", mcpOAuthCallbackPorts)
}

func beginMCPOAuth(connectionID uuid.UUID, redirectURI string) (string, error) {
	base := httpBaseURL()
	authHeaders, err := requestAuth(base)
	if err != nil {
		return "", err
	}
	endpoint := fmt.Sprintf("%s/api/v1/mcp/connections/%s/oauth/connect?redirectUri=%s", base, connectionID, url.QueryEscape(redirectURI))
	ctx, cancel := reqCtx()
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	for name, value := range authHeaders {
		req.Header.Set(name, value)
	}
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if response.StatusCode != http.StatusOK {
		return "", apiError("begin MCP OAuth", response.Status, body)
	}
	var result struct {
		AuthorizeURL string `json:"authorizeUrl"`
	}
	if err := json.Unmarshal(body, &result); err != nil || result.AuthorizeURL == "" {
		return "", fmt.Errorf("vault returned an invalid MCP OAuth response")
	}
	return result.AuthorizeURL, nil
}

func mcpOAuthCallbackHandler(vaultBase, wantState string, result chan<- error) http.Handler {
	vaultURL, parseErr := url.Parse(vaultBase)
	validVaultBase := parseErr == nil && vaultURL.User == nil && vaultURL.Fragment == "" &&
		(vaultURL.Scheme == "https" || (vaultURL.Scheme == "http" && (vaultURL.Hostname() == "127.0.0.1" || vaultURL.Hostname() == "localhost")))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/callback" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("state") != wantState {
			http.Error(w, "OAuth state mismatch", http.StatusBadRequest)
			return
		}
		if !validVaultBase {
			http.Error(w, "Invalid Vault address.", http.StatusBadGateway)
			select {
			case result <- fmt.Errorf("invalid Vault callback base URL"):
			default:
			}
			return
		}
		callbackURL := strings.TrimRight(vaultURL.String(), "/") + "/api/mcp/oauth/callback?" + r.URL.RawQuery
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, callbackURL, nil) //nolint:gosec // vaultURL was restricted to HTTPS or loopback HTTP above.
		if err == nil {
			var response *http.Response
			client := &http.Client{
				Timeout:       20 * time.Second,
				CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
			}
			response, err = client.Do(req) //nolint:gosec // request host is the validated configured Vault address.
			if response != nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
				_ = response.Body.Close()
				if response.StatusCode < 200 || response.StatusCode >= 400 {
					err = fmt.Errorf("vault rejected the OAuth callback: %s", response.Status)
				}
			}
		}
		if err != nil {
			http.Error(w, "MCP OAuth authorization failed; return to the terminal.", http.StatusBadGateway)
		} else {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, "<!doctype html><title>Connected</title><p>MCP authorization completed. You can close this window.</p>")
		}
		select {
		case result <- err:
		default:
		}
	})
}

func openBrowser(target string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", target) //nolint:gosec // target is the validated OAuth authorization URL.
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", target) //nolint:gosec // fixed browser launcher.
	default:
		command = exec.Command("xdg-open", target) //nolint:gosec // target is the validated OAuth authorization URL.
	}
	return command.Start()
}
