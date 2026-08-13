package mcpoauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

type memoryRepository struct {
	mu            sync.Mutex
	config        *ConnectionOAuth
	states        map[string]*State
	authorization *Authorization
	err           error
	claimErr      error
	saveErr       error
	upsertErr     error
}

func (r *memoryRepository) SaveClientConfiguration(_ context.Context, configuration *ClientConfiguration) error {
	if r.saveErr != nil {
		return r.saveErr
	}
	r.config = &ConnectionOAuth{
		ConnectionID: configuration.ConnectionID, UserID: configuration.UserID, TenantID: configuration.TenantID,
		Issuer: configuration.Issuer, ClientIDCipher: configuration.ClientIDCipher,
		ClientSecretCipher: configuration.ClientSecretCipher, Scopes: configuration.Scopes,
	}
	return nil
}

func (r *memoryRepository) GetConnectionOAuth(context.Context, uuid.UUID, uuid.UUID) (*ConnectionOAuth, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.config, nil
}

func (r *memoryRepository) SaveState(_ context.Context, state *State) error {
	if r.saveErr != nil {
		return r.saveErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.states == nil {
		r.states = make(map[string]*State)
	}
	r.states[state.State] = state
	return nil
}

func (r *memoryRepository) ClaimState(_ context.Context, state string) (*State, error) {
	if r.claimErr != nil {
		return nil, r.claimErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	row := r.states[state]
	delete(r.states, state)
	return row, nil
}

func (r *memoryRepository) GetAuthorization(context.Context, uuid.UUID, uuid.UUID) (*Authorization, error) {
	if r.err != nil {
		return nil, r.err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.authorization, nil
}

func (r *memoryRepository) UpsertAuthorization(_ context.Context, authorization *Authorization) error {
	if r.upsertErr != nil {
		return r.upsertErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.authorization = authorization
	return nil
}

type plainCipher struct {
	encryptErr error
	decryptErr error
	encryptAt  int
	calls      int
}

func (c *plainCipher) Encrypt(value []byte) ([]byte, error) { return c.EncryptString(string(value)) }
func (c *plainCipher) Decrypt(value []byte) ([]byte, error) {
	result, err := c.DecryptToString(value)
	return []byte(result), err
}
func (c *plainCipher) EncryptString(value string) ([]byte, error) {
	c.calls++
	if c.encryptErr != nil && (c.encryptAt == 0 || c.encryptAt == c.calls) {
		return nil, c.encryptErr
	}
	return []byte("encrypted:" + value), nil
}
func (c *plainCipher) DecryptToString(value []byte) (string, error) {
	if c.decryptErr != nil {
		return "", c.decryptErr
	}
	return strings.TrimPrefix(string(value), "encrypted:"), nil
}

type oauthServer struct {
	server       *httptest.Server
	resource     string
	issuer       string
	tokenStatus  int
	tokenBody    string
	metadataCode int
	tokenCalls   atomic.Int32
	lastForm     url.Values
	basicUser    string
	basicSecret  string
	mu           sync.Mutex
}

func newOAuthServer(t *testing.T) *oauthServer {
	t.Helper()
	f := &oauthServer{tokenStatus: http.StatusOK, metadataCode: http.StatusOK,
		tokenBody: `{"access_token":"access-one","refresh_token":"refresh-one","token_type":"bearer","expires_in":3600,"scope":"read write"}`}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-protected-resource/mcp":
			w.WriteHeader(f.metadataCode)
			_, _ = io.WriteString(w, `{"resource":`+quote(f.resource)+`,"authorization_servers":[`+quote(f.issuer)+`],"scopes_supported":["read","write"]}`)
		case "/.well-known/oauth-authorization-server":
			w.WriteHeader(f.metadataCode)
			_, _ = io.WriteString(w, `{"issuer":`+quote(f.issuer)+`,"authorization_endpoint":`+quote(f.server.URL+"/authorize")+`,"token_endpoint":`+quote(f.server.URL+"/token")+`,"token_endpoint_auth_methods_supported":["client_secret_basic"],"code_challenge_methods_supported":["S256"]}`)
		case "/token":
			f.tokenCalls.Add(1)
			_ = r.ParseForm()
			f.mu.Lock()
			f.lastForm = r.Form
			f.basicUser, f.basicSecret, _ = r.BasicAuth()
			f.mu.Unlock()
			w.WriteHeader(f.tokenStatus)
			_, _ = io.WriteString(w, f.tokenBody)
		default:
			http.NotFound(w, r)
		}
	}))
	f.resource = f.server.URL + "/mcp"
	f.issuer = f.server.URL
	t.Cleanup(f.server.Close)
	return f
}

func quote(value string) string { return `"` + value + `"` }

func newFixture(t *testing.T) (*Service, *memoryRepository, *oauthServer, uuid.UUID) {
	t.Helper()
	server := newOAuthServer(t)
	id := uuid.New()
	repository := &memoryRepository{config: &ConnectionOAuth{
		ConnectionID: id, Resource: server.resource, Issuer: server.issuer,
		ClientIDCipher: []byte("encrypted:client-id"), ClientSecretCipher: []byte("encrypted:client-secret"),
		Scopes: []string{"read", "write"},
	}}
	service := NewService(repository, &plainCipher{}, server.server.Client())
	service.now = func() time.Time { return time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC) }
	return service, repository, server, id
}

func TestAuthorizationFlowAndLiveToken(t *testing.T) {
	service, repository, upstream, connectionID := newFixture(t)

	discovery, err := service.Discover(context.Background(), connectionID)
	if err != nil {
		t.Fatal(err)
	}
	if discovery.Resource.Resource != upstream.resource || discovery.AuthorizationServer.Issuer != upstream.issuer || discovery.TokenAuthMethod != "client_secret_basic" {
		t.Fatalf("unexpected discovery: %+v", discovery)
	}

	begin, err := service.Begin(context.Background(), connectionID, "https://vault.example/api/mcp/oauth/callback")
	if err != nil {
		t.Fatal(err)
	}
	authorizeURL, err := url.Parse(begin.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	query := authorizeURL.Query()
	for key, want := range map[string]string{
		"client_id": "client-id", "resource": upstream.resource, "scope": "read write",
		"state": begin.State, "code_challenge_method": "S256", "redirect_uri": "https://vault.example/api/mcp/oauth/callback",
	} {
		if got := query.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if query.Get("code_challenge") == "" || repository.states[begin.State].CodeVerifier == "" {
		t.Fatal("PKCE values were not generated")
	}

	token, err := service.Complete(context.Background(), "authorization-code", begin.State)
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != "access-one" || token.TokenType != "Bearer" || !slices.Equal(token.Scopes, []string{"read", "write"}) {
		t.Fatalf("unexpected token: %+v", token)
	}
	if repository.states[begin.State] != nil {
		t.Fatal("callback state was not consumed")
	}
	if repository.authorization.Resource != upstream.resource || repository.authorization.Issuer != upstream.issuer || string(repository.authorization.AccessTokenCipher) != "encrypted:access-one" || string(repository.authorization.RefreshTokenCipher) != "encrypted:refresh-one" {
		t.Fatalf("unexpected stored authorization: %+v", repository.authorization)
	}
	upstream.mu.Lock()
	if upstream.basicUser != "client-id" || upstream.basicSecret != "client-secret" || upstream.lastForm.Get("resource") != upstream.resource || upstream.lastForm.Get("code_verifier") == "" {
		t.Errorf("unexpected token request: user=%q secret=%q form=%v", upstream.basicUser, upstream.basicSecret, upstream.lastForm)
	}
	upstream.mu.Unlock()

	live, err := service.AccessToken(context.Background(), connectionID)
	if err != nil {
		t.Fatal(err)
	}
	if live.AccessToken != "access-one" || upstream.tokenCalls.Load() != 1 {
		t.Fatalf("live token = %+v, token calls = %d", live, upstream.tokenCalls.Load())
	}
}

func TestConfigureClient(t *testing.T) {
	service, repository, upstream, connectionID := newFixture(t)
	if err := service.ConfigureClient(context.Background(), uuid.Nil, "", "client", "", nil); err == nil {
		t.Fatal("expected missing connection error")
	}
	if err := service.ConfigureClient(context.Background(), connectionID, "", " ", "", nil); err == nil {
		t.Fatal("expected missing client error")
	}
	if err := service.ConfigureClient(context.Background(), connectionID, "http://example.com", "client", "", nil); err == nil {
		t.Fatal("expected issuer validation error")
	}
	if err := service.ConfigureClient(context.Background(), connectionID, upstream.issuer, "new-client", "new-secret", []string{"read", "", "read", " write "}); err != nil {
		t.Fatal(err)
	}
	if string(repository.config.ClientIDCipher) != "encrypted:new-client" || string(repository.config.ClientSecretCipher) != "encrypted:new-secret" || !slices.Equal(repository.config.Scopes, []string{"read", "write"}) {
		t.Fatalf("unexpected client configuration: %+v", repository.config)
	}
	service.cipher = &plainCipher{encryptErr: errors.New("encrypt failed"), encryptAt: 1}
	if err := service.ConfigureClient(context.Background(), connectionID, "", "client", "secret", nil); err == nil {
		t.Fatal("expected client encryption error")
	}
	service.cipher = &plainCipher{encryptErr: errors.New("encrypt failed"), encryptAt: 2}
	if err := service.ConfigureClient(context.Background(), connectionID, "", "client", "secret", nil); err == nil {
		t.Fatal("expected secret encryption error")
	}
	service.cipher = &plainCipher{}
	repository.saveErr = errors.New("save failed")
	if err := service.ConfigureClient(context.Background(), connectionID, "", "client", "", nil); err == nil {
		t.Fatal("expected persistence error")
	}
}

func TestRefreshRotatesAndSerializes(t *testing.T) {
	service, repository, upstream, connectionID := newFixture(t)
	now := service.now().UTC()
	repository.authorization = &Authorization{
		ConnectionID: connectionID, Resource: upstream.resource, Issuer: upstream.issuer,
		TokenEndpoint: upstream.server.URL + "/token", TokenAuthMethod: "client_secret_basic",
		AccessTokenCipher: []byte("encrypted:old-access"), RefreshTokenCipher: []byte("encrypted:old-refresh"),
		TokenType: "Bearer", Scopes: []string{"old-scope"}, ExpiresAt: ptrTime(now.Add(5 * time.Second)),
	}
	upstream.tokenBody = `{"access_token":"new-access","refresh_token":"new-refresh","expires_in":7200}`

	var wg sync.WaitGroup
	errorsFound := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := service.AccessToken(context.Background(), connectionID)
			if err == nil && (token.AccessToken != "new-access" || !slices.Equal(token.Scopes, []string{"old-scope"})) {
				err = errors.New("unexpected refreshed token")
			}
			errorsFound <- err
		}()
	}
	wg.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls := upstream.tokenCalls.Load(); calls != 1 {
		t.Fatalf("refresh endpoint called %d times, want 1", calls)
	}
	if string(repository.authorization.RefreshTokenCipher) != "encrypted:new-refresh" || string(repository.authorization.AccessTokenCipher) != "encrypted:new-access" {
		t.Fatalf("rotated token set not persisted: %+v", repository.authorization)
	}
}

func TestRefreshPreservesUnrotatedRefreshToken(t *testing.T) {
	service, repository, upstream, connectionID := newFixture(t)
	repository.authorization = &Authorization{
		ConnectionID: connectionID, Resource: upstream.resource, Issuer: upstream.issuer,
		TokenEndpoint: upstream.server.URL + "/token", TokenAuthMethod: "client_secret_basic",
		AccessTokenCipher: []byte("encrypted:old-access"), RefreshTokenCipher: []byte("encrypted:old-refresh"),
		Scopes: []string{"read"}, ExpiresAt: ptrTime(service.now().Add(time.Second)),
	}
	upstream.tokenBody = `{"access_token":"new-access","token_type":"Bearer","expires_in":60,"scope":"new"}`
	result, err := service.AccessToken(context.Background(), connectionID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Scopes[0] != "new" || string(repository.authorization.RefreshTokenCipher) != "encrypted:old-refresh" {
		t.Fatalf("unexpected refreshed authorization: %+v", repository.authorization)
	}
}

func TestAccessTokenWithoutRefreshReturnsStoredToken(t *testing.T) {
	service, repository, upstream, connectionID := newFixture(t)
	repository.authorization = &Authorization{
		ConnectionID: connectionID, Resource: upstream.resource, Issuer: upstream.issuer,
		AccessTokenCipher: []byte("encrypted:still-valid-to-caller"), ExpiresAt: ptrTime(service.now().Add(-time.Hour)),
	}
	token, err := service.AccessToken(context.Background(), connectionID)
	if err != nil || token.AccessToken != "still-valid-to-caller" || upstream.tokenCalls.Load() != 0 {
		t.Fatalf("token=%+v calls=%d err=%v", token, upstream.tokenCalls.Load(), err)
	}
}

func TestFlowErrors(t *testing.T) {
	service, repository, upstream, connectionID := newFixture(t)
	originalConfig := repository.config
	t.Run("missing config", func(t *testing.T) {
		repository.config = nil
		if _, err := service.Discover(context.Background(), connectionID); err == nil {
			t.Fatal("expected error")
		}
		if _, err := service.Begin(context.Background(), connectionID, "https://vault.example/callback"); err == nil {
			t.Fatal("expected error")
		}
		repository.config = originalConfig
	})
	t.Run("repository errors", func(t *testing.T) {
		repository.err = errors.New("database failed")
		if _, err := service.Discover(context.Background(), connectionID); err == nil {
			t.Fatal("expected error")
		}
		if _, err := service.Begin(context.Background(), connectionID, "https://vault.example/callback"); err == nil {
			t.Fatal("expected error")
		}
		if _, err := service.AccessToken(context.Background(), connectionID); err == nil {
			t.Fatal("expected error")
		}
		repository.err = nil
	})
	t.Run("redirect", func(t *testing.T) {
		if _, err := service.Begin(context.Background(), connectionID, "http://vault.example/callback"); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("save", func(t *testing.T) {
		repository.saveErr = errors.New("save failed")
		if _, err := service.Begin(context.Background(), connectionID, "https://vault.example/callback"); err == nil {
			t.Fatal("expected error")
		}
		repository.saveErr = nil
	})
	t.Run("claim", func(t *testing.T) {
		repository.claimErr = errors.New("claim failed")
		if _, err := service.Complete(context.Background(), "code", "state"); err == nil {
			t.Fatal("expected error")
		}
		repository.claimErr = nil
		for _, input := range [][2]string{{"", "state"}, {"code", ""}, {"code", "unknown"}} {
			if _, err := service.Complete(context.Background(), input[0], input[1]); !errors.Is(err, ErrInvalidState) {
				t.Fatalf("Complete%v error = %v", input, err)
			}
		}
	})
	t.Run("expired and replay", func(t *testing.T) {
		repository.states = map[string]*State{"expired": {State: "expired", ExpiresAt: service.now().Add(-time.Second)}}
		if _, err := service.Complete(context.Background(), "code", "expired"); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("error = %v", err)
		}
		if _, err := service.Complete(context.Background(), "code", "expired"); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("replay error = %v", err)
		}
	})
	t.Run("callback binding", func(t *testing.T) {
		repository.states = map[string]*State{"bound": {
			State: "bound", ConnectionID: connectionID, ExpiresAt: service.now().Add(time.Minute),
			Resource: "http://localhost/other", Issuer: upstream.issuer,
		}}
		if _, err := service.Complete(context.Background(), "code", "bound"); !errors.Is(err, ErrBindingMismatch) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("upsert", func(t *testing.T) {
		begin, err := service.Begin(context.Background(), connectionID, "https://vault.example/callback")
		if err != nil {
			t.Fatal(err)
		}
		repository.upsertErr = errors.New("upsert failed")
		if _, err := service.Complete(context.Background(), "code", begin.State); err == nil {
			t.Fatal("expected error")
		}
		repository.upsertErr = nil
	})
}

func TestDiscoveryValidation(t *testing.T) {
	service, repository, upstream, connectionID := newFixture(t)
	t.Run("missing identifiers", func(t *testing.T) {
		for _, config := range []*ConnectionOAuth{{Resource: upstream.resource}, {ConnectionID: connectionID}} {
			if _, err := service.discover(context.Background(), config); err == nil {
				t.Fatal("expected error")
			}
		}
	})
	t.Run("resource endpoint", func(t *testing.T) {
		repository.config.Resource = "http://example.com/mcp"
		if _, err := service.Discover(context.Background(), connectionID); err == nil {
			t.Fatal("expected HTTPS error")
		}
		repository.config.Resource = upstream.resource
	})
	t.Run("metadata status", func(t *testing.T) {
		upstream.metadataCode = http.StatusBadGateway
		if _, err := service.Discover(context.Background(), connectionID); err == nil {
			t.Fatal("expected metadata error")
		}
		upstream.metadataCode = http.StatusOK
	})
	t.Run("resource binding", func(t *testing.T) {
		original := upstream.resource
		upstream.resource = upstream.server.URL + "/different"
		if _, err := service.Discover(context.Background(), connectionID); !errors.Is(err, ErrBindingMismatch) {
			t.Fatalf("error = %v", err)
		}
		upstream.resource = original
	})
	t.Run("configured issuer binding", func(t *testing.T) {
		original := repository.config.Issuer
		repository.config.Issuer = upstream.server.URL + "/unadvertised"
		if _, err := service.Discover(context.Background(), connectionID); !errors.Is(err, ErrBindingMismatch) {
			t.Fatalf("error = %v", err)
		}
		repository.config.Issuer = original
	})
}

type scriptedTransport struct {
	responses map[string]string
	status    int
}

func (s scriptedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, ok := s.responses[request.URL.String()]
	if !ok {
		return nil, errors.New("unexpected metadata URL")
	}
	status := s.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
}

func TestDiscoveryMetadataVariants(t *testing.T) {
	connectionID := uuid.New()
	resource := "https://mcp.example.com/path"
	resourceMetadataURL, _ := protectedResourceMetadataURL(resource)
	issuer := "https://idp.example.com/tenant"
	serverMetadataURL, _ := authorizationServerMetadataURL(issuer)
	baseResource := `{"resource":"https://mcp.example.com/path","authorization_servers":["https://idp.example.com/tenant"]}`
	validServer := `{"issuer":"https://idp.example.com/tenant","authorization_endpoint":"https://idp.example.com/authorize","token_endpoint":"https://idp.example.com/token","token_endpoint_auth_methods_supported":["none"],"code_challenge_methods_supported":["S256"]}`
	config := &ConnectionOAuth{ConnectionID: connectionID, Resource: resource, ClientIDCipher: []byte("client")}

	tests := []struct {
		name     string
		resource string
		server   string
	}{
		{"invalid resource JSON", `{`, validServer},
		{"missing issuer", `{"resource":"https://mcp.example.com/path"}`, validServer},
		{"invalid server JSON", baseResource, `{`},
		{"issuer mismatch", baseResource, strings.Replace(validServer, issuer, "https://other.example.com", 1)},
		{"missing endpoints", baseResource, `{"issuer":"https://idp.example.com/tenant"}`},
		{"invalid authorize", baseResource, strings.Replace(validServer, "https://idp.example.com/authorize", "http://idp.example.com/authorize", 1)},
		{"invalid token", baseResource, strings.Replace(validServer, "https://idp.example.com/token", "http://idp.example.com/token", 1)},
		{"no S256", baseResource, strings.Replace(validServer, `"S256"`, `"plain"`, 1)},
		{"no auth method", baseResource, strings.Replace(validServer, `"none"`, `"private_key_jwt"`, 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: scriptedTransport{responses: map[string]string{
				resourceMetadataURL: test.resource, serverMetadataURL: test.server,
			}}}
			service := NewService(&memoryRepository{}, &plainCipher{}, client)
			if _, err := service.discover(context.Background(), config); err == nil {
				t.Fatal("expected discovery error")
			}
		})
	}

	t.Run("custom resource metadata and inferred issuer", func(t *testing.T) {
		custom := "https://metadata.example.com/resource"
		configured := *config
		configured.ProtectedResourceMetadataURL = custom
		client := &http.Client{Transport: scriptedTransport{responses: map[string]string{
			custom: baseResource, serverMetadataURL: validServer,
		}}}
		service := NewService(&memoryRepository{}, &plainCipher{}, client)
		discovery, err := service.discover(context.Background(), &configured)
		if err != nil || discovery.AuthorizationServer.Issuer != issuer {
			t.Fatalf("discovery=%+v err=%v", discovery, err)
		}
	})
}

func TestBeginAndTokenCipherErrors(t *testing.T) {
	service, repository, upstream, connectionID := newFixture(t)
	service.cipher = &plainCipher{decryptErr: errors.New("decrypt failed")}
	if _, err := service.Begin(context.Background(), connectionID, "https://vault.example/callback"); err == nil {
		t.Fatal("expected client ID decrypt error")
	}
	service.cipher = &plainCipher{}
	repository.config.ClientIDCipher = nil
	if _, err := service.Begin(context.Background(), connectionID, "https://vault.example/callback"); err == nil {
		t.Fatal("expected empty client ID error")
	}
	repository.config.ClientIDCipher = []byte("encrypted:client")
	repository.authorization = &Authorization{
		ConnectionID: connectionID, Resource: upstream.resource, Issuer: upstream.issuer,
		AccessTokenCipher: []byte("encrypted:a"), ExpiresAt: ptrTime(service.now().Add(time.Hour)),
	}
	service.cipher = &plainCipher{decryptErr: errors.New("decrypt failed")}
	if _, err := service.AccessToken(context.Background(), connectionID); err == nil {
		t.Fatal("expected live token decrypt error")
	}
}

func TestHelperValidation(t *testing.T) {
	for _, test := range []struct {
		value string
		ok    bool
	}{
		{"https://example.com/path?x=1", true}, {"http://localhost/path", true}, {"http://127.0.0.1/path", true},
		{"http://[::1]/path", true}, {"http://example.com", false}, {"ftp://example.com", false},
		{"https://user@example.com", false}, {"https://example.com/#fragment", false}, {"://bad", false},
	} {
		if err := validateEndpoint(test.value); (err == nil) != test.ok {
			t.Errorf("validateEndpoint(%q) error = %v, want ok=%v", test.value, err, test.ok)
		}
	}
	for _, test := range []struct {
		value string
		ok    bool
	}{
		{"https://vault.example/callback", true}, {"http://localhost/callback", true},
		{"http://vault.example/callback", false}, {"not-a-url", false}, {"https://vault.example/callback#x", false},
	} {
		if err := validateRedirectURI(test.value); (err == nil) != test.ok {
			t.Errorf("validateRedirectURI(%q) error = %v, want ok=%v", test.value, err, test.ok)
		}
	}

	resource, err := protectedResourceMetadataURL("https://example.com/mcp/path?ignored=yes")
	if err != nil || resource != "https://example.com/.well-known/oauth-protected-resource/mcp/path" {
		t.Fatalf("resource metadata URL = %q, %v", resource, err)
	}
	issuer, err := authorizationServerMetadataURL("https://idp.example.com/tenant?ignored=yes")
	if err != nil || issuer != "https://idp.example.com/.well-known/oauth-authorization-server/tenant" {
		t.Fatalf("issuer metadata URL = %q, %v", issuer, err)
	}

	for _, test := range []struct {
		supported []string
		secret    bool
		want      string
		wantErr   bool
	}{
		{nil, true, "client_secret_basic", false}, {nil, false, "none", false},
		{[]string{"client_secret_post"}, true, "client_secret_post", false},
		{[]string{"none"}, false, "none", false}, {[]string{"none"}, true, "", true},
	} {
		got, err := chooseTokenAuthMethod(test.supported, test.secret)
		if got != test.want || (err != nil) != test.wantErr {
			t.Errorf("chooseTokenAuthMethod(%v, %v) = %q, %v", test.supported, test.secret, got, err)
		}
	}
	if _, err := selectIssuer("", nil); err == nil {
		t.Fatal("expected missing issuer error")
	}
	if _, err := selectIssuer("http://example.com", nil); err == nil {
		t.Fatal("expected invalid issuer error")
	}
}

func TestTokenResponseErrorsAndCipherFailures(t *testing.T) {
	service, repository, upstream, connectionID := newFixture(t)
	state := func(value string) {
		repository.states = map[string]*State{value: {
			State: value, ConnectionID: connectionID, CodeVerifier: "verifier",
			RedirectURI: "https://vault.example/callback", Resource: upstream.resource,
			Issuer: upstream.issuer, TokenEndpoint: upstream.server.URL + "/token", TokenAuthMethod: "client_secret_basic",
			Scopes: []string{"read"}, ExpiresAt: service.now().Add(time.Minute),
		}}
	}
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"status", http.StatusBadRequest, `{}`}, {"invalid", http.StatusOK, `{`},
		{"missing", http.StatusOK, `{}`}, {"token type", http.StatusOK, `{"access_token":"a","token_type":"mac"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state(test.name)
			upstream.tokenStatus, upstream.tokenBody = test.status, test.body
			if _, err := service.Complete(context.Background(), "code", test.name); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	upstream.tokenStatus = http.StatusOK
	upstream.tokenBody = `{"access_token":"a","refresh_token":"r"}`
	for _, failAt := range []int{1, 2} {
		state("cipher")
		service.cipher = &plainCipher{encryptErr: errors.New("encrypt failed"), encryptAt: failAt}
		if _, err := service.Complete(context.Background(), "code", "cipher"); err == nil {
			t.Fatalf("expected encryption error at call %d", failAt)
		}
	}
	service.cipher = &plainCipher{decryptErr: errors.New("decrypt failed")}
	state("decrypt")
	if _, err := service.Complete(context.Background(), "code", "decrypt"); err == nil {
		t.Fatal("expected decrypt error")
	}
}

func TestAccessTokenErrors(t *testing.T) {
	service, repository, upstream, connectionID := newFixture(t)
	if _, err := service.AccessToken(context.Background(), connectionID); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("error = %v", err)
	}
	repository.authorization = &Authorization{ConnectionID: connectionID, Resource: "http://localhost/other"}
	if _, err := service.AccessToken(context.Background(), connectionID); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("error = %v", err)
	}
	repository.authorization = &Authorization{
		ConnectionID: connectionID, Resource: upstream.resource, Issuer: upstream.issuer,
		AccessTokenCipher: []byte("encrypted:a"), RefreshTokenCipher: []byte("encrypted:r"),
		TokenEndpoint: upstream.server.URL + "/token", TokenAuthMethod: "client_secret_basic", ExpiresAt: ptrTime(service.now()),
	}
	service.cipher = &plainCipher{decryptErr: errors.New("decrypt failed")}
	if _, err := service.AccessToken(context.Background(), connectionID); err == nil {
		t.Fatal("expected decrypt error")
	}
	service.cipher = &plainCipher{}
	upstream.tokenStatus = http.StatusInternalServerError
	if _, err := service.AccessToken(context.Background(), connectionID); err == nil {
		t.Fatal("expected refresh HTTP error")
	}
	upstream.tokenStatus = http.StatusOK
	upstream.tokenBody = `{"access_token":"new"}`
	repository.upsertErr = errors.New("upsert failed")
	if _, err := service.AccessToken(context.Background(), connectionID); err == nil {
		t.Fatal("expected upsert error")
	}
}

func TestAdditionalErrorPaths(t *testing.T) {
	service, repository, upstream, connectionID := newFixture(t)
	if _, err := service.exchange(context.Background(), repository.config, "http://example.com/token", "none", url.Values{}); err == nil {
		t.Fatal("expected invalid token endpoint error")
	}
	if err := service.getJSON(context.Background(), "http://example.com/metadata", &map[string]string{}); err == nil {
		t.Fatal("expected invalid metadata endpoint error")
	}
	if _, err := selectIssuer("", []string{"http://example.com"}); err == nil {
		t.Fatal("expected invalid advertised issuer")
	}
	if _, err := protectedResourceMetadataURL("://bad"); err == nil {
		t.Fatal("expected invalid resource URL")
	}
	if _, err := authorizationServerMetadataURL("://bad"); err == nil {
		t.Fatal("expected invalid issuer URL")
	}

	repository.states = map[string]*State{"state": {
		State: "state", ConnectionID: connectionID, ExpiresAt: service.now().Add(time.Minute),
		Resource: upstream.resource, Issuer: upstream.issuer,
	}}
	repository.err = errors.New("database failed")
	if _, err := service.Complete(context.Background(), "code", "state"); err == nil {
		t.Fatal("expected callback configuration error")
	}
	repository.err = nil

	repository.authorization = &Authorization{
		ConnectionID: connectionID, Resource: upstream.resource, Issuer: upstream.issuer,
		TokenEndpoint: upstream.server.URL + "/token", TokenAuthMethod: "client_secret_basic",
		AccessTokenCipher: []byte("encrypted:a"), RefreshTokenCipher: []byte("encrypted:r"), ExpiresAt: ptrTime(service.now()),
	}
	upstream.tokenBody = `{"access_token":"new","refresh_token":"rotated"}`
	service.cipher = &plainCipher{encryptErr: errors.New("encrypt failed"), encryptAt: 1}
	if _, err := service.AccessToken(context.Background(), connectionID); err == nil {
		t.Fatal("expected refreshed access encryption error")
	}
	service.cipher = &plainCipher{encryptErr: errors.New("encrypt failed"), encryptAt: 2}
	if _, err := service.AccessToken(context.Background(), connectionID); err == nil {
		t.Fatal("expected refreshed token encryption error")
	}
}

func TestClientSecretPostAndPublicClient(t *testing.T) {
	for _, authMethod := range []string{"client_secret_post", "none"} {
		t.Run(authMethod, func(t *testing.T) {
			service, repository, upstream, connectionID := newFixture(t)
			if authMethod == "none" {
				repository.config.ClientSecretCipher = nil
			}
			repository.states = map[string]*State{"state": {
				State: "state", ConnectionID: connectionID, CodeVerifier: "verifier",
				RedirectURI: "https://vault.example/callback", Resource: upstream.resource,
				Issuer: upstream.issuer, TokenEndpoint: upstream.server.URL + "/token", TokenAuthMethod: authMethod,
				ExpiresAt: service.now().Add(time.Minute),
			}}
			if _, err := service.Complete(context.Background(), "code", "state"); err != nil {
				t.Fatal(err)
			}
			upstream.mu.Lock()
			defer upstream.mu.Unlock()
			if authMethod == "client_secret_post" && upstream.lastForm.Get("client_secret") != "client-secret" {
				t.Fatalf("form = %v", upstream.lastForm)
			}
			if authMethod == "none" && upstream.lastForm.Get("client_secret") != "" {
				t.Fatalf("form = %v", upstream.lastForm)
			}
		})
	}
}

func TestDefaultClientAndRedirectPolicy(t *testing.T) {
	repository := &memoryRepository{}
	service := NewService(repository, &plainCipher{}, nil)
	if service.client == nil || service.client.Transport == nil || service.client.CheckRedirect == nil {
		t.Fatal("default safe client not configured")
	}
	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err := service.client.CheckRedirect(req, nil); err == nil {
		t.Fatal("expected redirect validation error")
	}
	req, _ = http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err := service.client.CheckRedirect(req, make([]*http.Request, 5)); err == nil {
		t.Fatal("expected redirect limit error")
	}
}

type errorTransport struct{}

func (errorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network failed")
}

func TestNetworkErrors(t *testing.T) {
	service, repository, upstream, connectionID := newFixture(t)
	service.client = &http.Client{Transport: errorTransport{}}
	if _, err := service.Discover(context.Background(), connectionID); err == nil {
		t.Fatal("expected discovery network error")
	}
	repository.authorization = &Authorization{
		ConnectionID: connectionID, Resource: upstream.resource, Issuer: upstream.issuer,
		TokenEndpoint: upstream.server.URL + "/token", TokenAuthMethod: "client_secret_basic",
		AccessTokenCipher: []byte("encrypted:a"), RefreshTokenCipher: []byte("encrypted:r"), ExpiresAt: ptrTime(service.now()),
	}
	if _, err := service.AccessToken(context.Background(), connectionID); err == nil {
		t.Fatal("expected refresh network error")
	}
}

func ptrTime(value time.Time) *time.Time { return &value }
