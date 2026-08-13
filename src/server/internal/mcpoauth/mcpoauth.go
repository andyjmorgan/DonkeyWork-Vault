// Package mcpoauth implements connection-bound OAuth authorization for upstream MCP servers.
package mcpoauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/crypto"
	"donkeywork.dev/vault-server/internal/httpx"
	"donkeywork.dev/vault-server/internal/oauth"
)

const (
	stateLifetime     = 10 * time.Minute
	refreshWindow     = 60 * time.Second
	maxMetadataBytes  = 1 << 20
	maxOAuthRedirects = 5
)

var (
	// ErrInvalidState means an authorization callback state is unknown, expired, or already used.
	ErrInvalidState = errors.New("invalid or expired MCP OAuth state")
	// ErrNotAuthorized means the connection has no stored upstream OAuth token set.
	ErrNotAuthorized = errors.New("MCP connection is not authorized")
	// ErrBindingMismatch means stored OAuth material is bound to another resource or issuer.
	ErrBindingMismatch = errors.New("MCP OAuth resource or issuer binding mismatch")
)

// ConnectionOAuth is the non-token OAuth configuration for one MCP connection.
type ConnectionOAuth struct {
	ConnectionID                 uuid.UUID
	UserID                       uuid.UUID
	TenantID                     uuid.UUID
	Resource                     string
	ProtectedResourceMetadataURL string
	Issuer                       string
	ClientIDCipher               []byte
	ClientSecretCipher           []byte
	Scopes                       []string
}

// ClientConfiguration contains encrypted OAuth client credentials before an upstream authorization
// has produced a token set.
type ClientConfiguration struct {
	ConnectionID       uuid.UUID
	UserID             uuid.UUID
	TenantID           uuid.UUID
	Issuer             string
	ClientIDCipher     []byte
	ClientSecretCipher []byte
	Scopes             []string
}

// State is a one-use authorization-code flow record. The discovered endpoints are captured so a
// callback cannot be redirected by metadata changing midway through the flow.
type State struct {
	State                 string
	ConnectionID          uuid.UUID
	UserID                uuid.UUID
	TenantID              uuid.UUID
	CodeVerifier          string
	RedirectURI           string
	Resource              string
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	TokenAuthMethod       string
	Scopes                []string
	ExpiresAt             time.Time
}

// Authorization is a connection-bound encrypted OAuth token set.
type Authorization struct {
	ConnectionID          uuid.UUID
	UserID                uuid.UUID
	TenantID              uuid.UUID
	Resource              string
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	TokenAuthMethod       string
	AccessTokenCipher     []byte
	RefreshTokenCipher    []byte
	TokenType             string
	Scopes                []string
	ExpiresAt             *time.Time
	LastRefreshedAt       time.Time
}

// Status is the secret-free OAuth state for one owner-scoped MCP connection.
type Status struct {
	ConnectionID    uuid.UUID
	Configured      bool
	Authorized      bool
	Issuer          string
	Resource        string
	Scopes          []string
	ExpiresAt       *time.Time
	LastRefreshedAt *time.Time
}

// Repository is the persistence boundary required by Service. ClaimState must atomically return
// and delete a state, returning nil after the first successful claim.
type Repository interface {
	GetConnectionOAuth(context.Context, uuid.UUID, uuid.UUID) (*ConnectionOAuth, error)
	GetStatus(context.Context, uuid.UUID, uuid.UUID) (*Status, error)
	WithRefreshLock(context.Context, uuid.UUID, func() error) error
	SaveClientConfiguration(context.Context, *ClientConfiguration) error
	DeleteAuthorization(context.Context, uuid.UUID, uuid.UUID) (bool, error)
	SaveState(context.Context, *State) error
	GetState(context.Context, string) (*State, error)
	ClaimState(context.Context, string) (*State, error)
	GetAuthorization(context.Context, uuid.UUID, uuid.UUID) (*Authorization, error)
	UpsertAuthorization(context.Context, *Authorization) error
}

// ProtectedResourceMetadata is the RFC 9728 metadata used by MCP OAuth discovery.
type ProtectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

// AuthorizationServerMetadata is the RFC 8414 subset needed for authorization-code + PKCE.
type AuthorizationServerMetadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	RegistrationEndpoint  string   `json:"registration_endpoint"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
	ScopesSupported       []string `json:"scopes_supported"`
}

// Discovery is validated metadata for an MCP connection.
type Discovery struct {
	Resource            ProtectedResourceMetadata
	AuthorizationServer AuthorizationServerMetadata
	TokenAuthMethod     string
}

// BeginResult contains the browser URL and anti-forgery state for a new authorization.
type BeginResult struct {
	AuthorizationURL string
	State            string
	ExpiresAt        time.Time
}

// Token is a live bearer token for injection into requests to the bound MCP resource.
type Token struct {
	AccessToken string
	TokenType   string
	Scopes      []string
	ExpiresAt   *time.Time
}

// Service discovers MCP OAuth metadata and maintains connection-bound token sets.
type Service struct {
	repository Repository
	cipher     crypto.Cipher
	client     *http.Client
	now        func() time.Time
	locks      connectionLocks
}

// NewService constructs an MCP OAuth service. A nil client selects an SSRF-hardened client.
func NewService(repository Repository, cipher crypto.Cipher, client *http.Client) *Service {
	if client == nil {
		client = &http.Client{
			Transport: httpx.DefaultSafeTransport(),
			Timeout:   20 * time.Second,
		}
	}
	serviceClient := *client
	callerRedirectPolicy := client.CheckRedirect
	serviceClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxOAuthRedirects {
			return errors.New("too many OAuth metadata redirects")
		}
		if len(via) > 0 && via[0] != nil && via[0].Method != http.MethodGet {
			return errors.New("OAuth token endpoint redirects are not allowed")
		}
		if err := validateEndpoint(req.URL.String()); err != nil {
			return err
		}
		if callerRedirectPolicy != nil {
			return callerRedirectPolicy(req, via)
		}
		return nil
	}
	return &Service{repository: repository, cipher: cipher, client: &serviceClient, now: time.Now, locks: connectionLocks{entries: make(map[uuid.UUID]*lockEntry)}}
}

// Status returns the caller's secret-free OAuth state, or nil when the connection is not visible.
func (s *Service) Status(ctx context.Context, connectionID uuid.UUID) (*Status, error) {
	if connectionID == uuid.Nil {
		return nil, errors.New("MCP connection ID is required")
	}
	return s.repository.GetStatus(ctx, contracts.CallerFrom(ctx).UserID, connectionID)
}

// ConfigureClient encrypts and stores an OAuth client registration for an MCP connection. Issuer
// may be empty to select the first authorization server advertised by resource metadata.
func (s *Service) ConfigureClient(ctx context.Context, connectionID uuid.UUID, issuer, clientID, clientSecret string, scopes []string) error {
	if connectionID == uuid.Nil || strings.TrimSpace(clientID) == "" {
		return errors.New("MCP connection ID and OAuth client ID are required")
	}
	if issuer != "" {
		if err := validateEndpoint(issuer); err != nil {
			return fmt.Errorf("invalid issuer: %w", err)
		}
	}
	clientIDCipher, err := s.cipher.EncryptString(clientID)
	if err != nil {
		return err
	}
	var clientSecretCipher []byte
	if clientSecret != "" {
		clientSecretCipher, err = s.cipher.EncryptString(clientSecret)
		if err != nil {
			return err
		}
	}
	caller := contracts.CallerFrom(ctx)
	configuration := &ClientConfiguration{
		ConnectionID: connectionID, UserID: caller.UserID, TenantID: caller.TenantID,
		Issuer: issuer, ClientIDCipher: clientIDCipher, ClientSecretCipher: clientSecretCipher,
		Scopes: normalizeScopes(scopes),
	}
	unlock := s.locks.lock(connectionID)
	defer unlock()
	return s.repository.WithRefreshLock(ctx, connectionID, func() error {
		return s.repository.SaveClientConfiguration(ctx, configuration)
	})
}

// DeleteAuthorization removes the caller's OAuth client configuration and token set.
func (s *Service) DeleteAuthorization(ctx context.Context, connectionID uuid.UUID) (bool, error) {
	if connectionID == uuid.Nil {
		return false, errors.New("MCP connection ID is required")
	}
	unlock := s.locks.lock(connectionID)
	defer unlock()
	var deleted bool
	err := s.repository.WithRefreshLock(ctx, connectionID, func() error {
		var err error
		deleted, err = s.repository.DeleteAuthorization(ctx, contracts.CallerFrom(ctx).UserID, connectionID)
		return err
	})
	return deleted, err
}

// Discover resolves and validates protected-resource and authorization-server metadata.
func (s *Service) Discover(ctx context.Context, connectionID uuid.UUID) (*Discovery, error) {
	config, err := s.repository.GetConnectionOAuth(ctx, contracts.CallerFrom(ctx).UserID, connectionID)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, fmt.Errorf("MCP connection %s has no OAuth configuration", connectionID)
	}
	return s.discover(ctx, config)
}

func (s *Service) discover(ctx context.Context, config *ConnectionOAuth) (*Discovery, error) {
	if config.ConnectionID == uuid.Nil || config.Resource == "" {
		return nil, errors.New("MCP OAuth connection ID and resource are required")
	}
	if err := validateEndpoint(config.Resource); err != nil {
		return nil, fmt.Errorf("invalid MCP resource: %w", err)
	}
	metadataURL := config.ProtectedResourceMetadataURL
	if metadataURL == "" {
		var err error
		metadataURL, err = protectedResourceMetadataURL(config.Resource)
		if err != nil {
			return nil, err
		}
	}
	var resourceMetadata ProtectedResourceMetadata
	if err := s.getJSON(ctx, metadataURL, &resourceMetadata); err != nil {
		return nil, fmt.Errorf("discover protected resource: %w", err)
	}
	if resourceMetadata.Resource != config.Resource {
		return nil, fmt.Errorf("%w: metadata resource %q does not match %q", ErrBindingMismatch, resourceMetadata.Resource, config.Resource)
	}

	issuer, err := selectIssuer(config.Issuer, resourceMetadata.AuthorizationServers)
	if err != nil {
		return nil, err
	}
	metadataEndpoint, err := authorizationServerMetadataURL(issuer)
	if err != nil {
		return nil, err
	}
	var serverMetadata AuthorizationServerMetadata
	if err := s.getJSON(ctx, metadataEndpoint, &serverMetadata); err != nil {
		return nil, fmt.Errorf("discover authorization server: %w", err)
	}
	if serverMetadata.Issuer != issuer {
		return nil, fmt.Errorf("%w: authorization metadata issuer %q does not match %q", ErrBindingMismatch, serverMetadata.Issuer, issuer)
	}
	if serverMetadata.AuthorizationEndpoint == "" || serverMetadata.TokenEndpoint == "" {
		return nil, errors.New("authorization server metadata omits required endpoints")
	}
	if err := validateEndpoint(serverMetadata.AuthorizationEndpoint); err != nil {
		return nil, fmt.Errorf("invalid authorization endpoint: %w", err)
	}
	if err := validateEndpoint(serverMetadata.TokenEndpoint); err != nil {
		return nil, fmt.Errorf("invalid token endpoint: %w", err)
	}
	if len(serverMetadata.CodeChallengeMethods) > 0 && !slices.Contains(serverMetadata.CodeChallengeMethods, "S256") {
		return nil, errors.New("authorization server does not support PKCE S256")
	}

	method, err := chooseTokenAuthMethod(serverMetadata.TokenAuthMethods, len(config.ClientSecretCipher) > 0)
	if err != nil {
		return nil, err
	}
	return &Discovery{Resource: resourceMetadata, AuthorizationServer: serverMetadata, TokenAuthMethod: method}, nil
}

// Begin discovers the authority, stores a one-time PKCE state, and returns the authorization URL.
func (s *Service) Begin(ctx context.Context, connectionID uuid.UUID, redirectURI string) (*BeginResult, error) {
	if err := validateRedirectURI(redirectURI); err != nil {
		return nil, err
	}
	caller := contracts.CallerFrom(ctx)
	config, err := s.repository.GetConnectionOAuth(ctx, caller.UserID, connectionID)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, fmt.Errorf("MCP connection %s has no OAuth configuration", connectionID)
	}
	discovery, err := s.discover(ctx, config)
	if err != nil {
		return nil, err
	}
	clientID, err := s.cipher.DecryptToString(config.ClientIDCipher)
	if err != nil {
		return nil, err
	}
	if clientID == "" {
		return nil, errors.New("MCP OAuth client ID is empty")
	}
	verifier, err := oauth.GenerateVerifier()
	if err != nil {
		return nil, err //coverage:ignore crypto/rand failure is covered by the oauth package
	}
	stateValue, err := oauth.RandomState()
	if err != nil {
		return nil, err //coverage:ignore crypto/rand failure is covered by the oauth package
	}
	expiresAt := s.now().UTC().Add(stateLifetime)
	state := &State{
		State: stateValue, ConnectionID: connectionID, UserID: caller.UserID, TenantID: caller.TenantID,
		CodeVerifier: verifier,
		RedirectURI:  redirectURI, Resource: config.Resource,
		Issuer:                discovery.AuthorizationServer.Issuer,
		AuthorizationEndpoint: discovery.AuthorizationServer.AuthorizationEndpoint,
		TokenEndpoint:         discovery.AuthorizationServer.TokenEndpoint,
		TokenAuthMethod:       discovery.TokenAuthMethod, Scopes: slices.Clone(config.Scopes), ExpiresAt: expiresAt,
	}
	unlock := s.locks.lock(connectionID)
	defer unlock()
	err = s.repository.WithRefreshLock(ctx, connectionID, func() error {
		current, loadErr := s.repository.GetConnectionOAuth(ctx, caller.UserID, connectionID)
		if loadErr != nil {
			return loadErr
		}
		if !sameConnectionOAuth(config, current) {
			return ErrBindingMismatch
		}
		return s.repository.SaveState(ctx, state)
	})
	if err != nil {
		return nil, err
	}
	values := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"state":                 {stateValue},
		"code_challenge":        {oauth.Challenge(verifier)},
		"code_challenge_method": {"S256"},
		"resource":              {config.Resource},
	}
	if len(config.Scopes) > 0 {
		values.Set("scope", strings.Join(config.Scopes, " "))
	}
	return &BeginResult{AuthorizationURL: discovery.AuthorizationServer.AuthorizationEndpoint + "?" + values.Encode(), State: stateValue, ExpiresAt: expiresAt}, nil
}

// Complete atomically claims a callback state, exchanges the code, and encrypts the token set.
func (s *Service) Complete(ctx context.Context, code, stateValue string) (*Token, error) {
	if code == "" || stateValue == "" {
		return nil, ErrInvalidState
	}
	peeked, err := s.repository.GetState(ctx, stateValue)
	if err != nil {
		return nil, err
	}
	if peeked == nil || peeked.State != stateValue || peeked.ConnectionID == uuid.Nil {
		return nil, ErrInvalidState
	}
	unlock := s.locks.lock(peeked.ConnectionID)
	defer unlock()
	var token *Token
	err = s.repository.WithRefreshLock(ctx, peeked.ConnectionID, func() error {
		state, claimErr := s.repository.ClaimState(ctx, stateValue)
		if claimErr != nil {
			return claimErr
		}
		if state == nil || state.State != stateValue || state.ConnectionID != peeked.ConnectionID || !state.ExpiresAt.After(s.now().UTC()) {
			return ErrInvalidState
		}
		config, loadErr := s.repository.GetConnectionOAuth(ctx, state.UserID, state.ConnectionID)
		if loadErr != nil {
			return loadErr
		}
		if config == nil || config.Resource != state.Resource || (config.Issuer != "" && config.Issuer != state.Issuer) {
			return ErrBindingMismatch
		}
		response, exchangeErr := s.exchange(ctx, config, state.TokenEndpoint, state.TokenAuthMethod, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {state.RedirectURI},
			"code_verifier": {state.CodeVerifier},
			"resource":      {state.Resource},
		})
		if exchangeErr != nil {
			return exchangeErr
		}
		authorization, completedToken, encryptErr := s.encryptResponse(state.ConnectionID, state.UserID, state.TenantID, state.Resource, state.Issuer, state.AuthorizationEndpoint, state.TokenEndpoint, state.TokenAuthMethod, state.Scopes, response)
		if encryptErr != nil {
			return encryptErr
		}
		current, loadErr := s.repository.GetConnectionOAuth(ctx, state.UserID, state.ConnectionID)
		if loadErr != nil {
			return loadErr
		}
		if !sameConnectionOAuth(config, current) {
			return ErrBindingMismatch
		}
		if persistErr := s.repository.UpsertAuthorization(ctx, authorization); persistErr != nil {
			return persistErr
		}
		token = completedToken
		return nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func sameConnectionOAuth(expected, current *ConnectionOAuth) bool {
	return expected != nil && current != nil && expected.ConnectionID == current.ConnectionID &&
		expected.UserID == current.UserID && expected.TenantID == current.TenantID &&
		expected.Resource == current.Resource && expected.Issuer == current.Issuer &&
		bytes.Equal(expected.ClientIDCipher, current.ClientIDCipher) &&
		bytes.Equal(expected.ClientSecretCipher, current.ClientSecretCipher) && slices.Equal(expected.Scopes, current.Scopes)
}

// AccessToken returns a live connection-bound token, refreshing close-to-expiry tokens.
func (s *Service) AccessToken(ctx context.Context, connectionID uuid.UUID) (*Token, error) {
	userID := contracts.CallerFrom(ctx).UserID
	config, authorization, err := s.boundAuthorization(ctx, userID, connectionID)
	if err != nil {
		return nil, err
	}
	if authorization.ExpiresAt == nil || authorization.ExpiresAt.After(s.now().UTC().Add(refreshWindow)) {
		return s.decryptToken(authorization)
	}
	if len(authorization.RefreshTokenCipher) == 0 {
		return s.decryptToken(authorization)
	}

	unlock := s.locks.lock(connectionID)
	defer unlock()
	var token *Token
	err = s.repository.WithRefreshLock(ctx, connectionID, func() error {
		// Another replica may have refreshed or reconfigured this connection while this caller waited.
		// Both records must therefore be re-read under the distributed lock.
		config, authorization, err = s.boundAuthorization(ctx, userID, connectionID)
		if err != nil {
			return err
		}
		if authorization.ExpiresAt == nil || authorization.ExpiresAt.After(s.now().UTC().Add(refreshWindow)) || len(authorization.RefreshTokenCipher) == 0 {
			token, err = s.decryptToken(authorization)
			return err
		}
		refreshToken, decryptErr := s.cipher.DecryptToString(authorization.RefreshTokenCipher)
		if decryptErr != nil {
			return decryptErr
		}
		response, exchangeErr := s.exchange(ctx, config, authorization.TokenEndpoint, authorization.TokenAuthMethod, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"resource":      {authorization.Resource},
		})
		if exchangeErr != nil {
			return exchangeErr
		}
		updated, refreshed, encryptErr := s.encryptResponse(connectionID, authorization.UserID, authorization.TenantID, authorization.Resource, authorization.Issuer, authorization.AuthorizationEndpoint, authorization.TokenEndpoint, authorization.TokenAuthMethod, authorization.Scopes, response)
		if encryptErr != nil {
			return encryptErr
		}
		if response.RefreshToken == "" {
			updated.RefreshTokenCipher = authorization.RefreshTokenCipher
		}
		if len(response.Scopes) == 0 {
			updated.Scopes = slices.Clone(authorization.Scopes)
			refreshed.Scopes = slices.Clone(authorization.Scopes)
		}
		if persistErr := s.repository.UpsertAuthorization(ctx, updated); persistErr != nil {
			return persistErr
		}
		token = refreshed
		return nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (s *Service) boundAuthorization(ctx context.Context, userID, connectionID uuid.UUID) (*ConnectionOAuth, *Authorization, error) {
	config, err := s.repository.GetConnectionOAuth(ctx, userID, connectionID)
	if err != nil {
		return nil, nil, err
	}
	authorization, err := s.repository.GetAuthorization(ctx, userID, connectionID)
	if err != nil {
		return nil, nil, err
	}
	if config == nil || authorization == nil {
		return nil, nil, ErrNotAuthorized
	}
	if config.Resource != authorization.Resource || (config.Issuer != "" && config.Issuer != authorization.Issuer) {
		return nil, nil, ErrBindingMismatch
	}
	return config, authorization, nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	Scopes       []string
}

type registrationRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope,omitempty"`
	ApplicationType         string   `json:"application_type"`
}

type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

func (s *Service) ensureClient(ctx context.Context, connectionID uuid.UUID, redirectURI string) error {
	caller := contracts.CallerFrom(ctx)
	config, err := s.repository.GetConnectionOAuth(ctx, caller.UserID, connectionID)
	if err != nil {
		return err
	}
	if config == nil {
		return fmt.Errorf("MCP connection %s not found", connectionID)
	}
	if len(config.ClientIDCipher) > 0 {
		return nil
	}
	unlock := s.locks.lock(connectionID)
	defer unlock()
	return s.repository.WithRefreshLock(ctx, connectionID, func() error {
		current, loadErr := s.repository.GetConnectionOAuth(ctx, caller.UserID, connectionID)
		if loadErr != nil {
			return loadErr
		}
		if current == nil {
			return fmt.Errorf("MCP connection %s not found", connectionID)
		}
		if len(current.ClientIDCipher) > 0 {
			return nil
		}
		discovery, discoverErr := s.discover(ctx, current)
		if discoverErr != nil {
			return discoverErr
		}
		registered, registerErr := s.register(ctx, discovery, redirectURI)
		if registerErr != nil {
			return registerErr
		}
		clientIDCipher, encryptErr := s.cipher.EncryptString(registered.ClientID)
		if encryptErr != nil {
			return encryptErr
		}
		var clientSecretCipher []byte
		if registered.ClientSecret != "" {
			clientSecretCipher, encryptErr = s.cipher.EncryptString(registered.ClientSecret)
			if encryptErr != nil {
				return encryptErr
			}
		}
		scopes := normalizeScopes(discovery.Resource.ScopesSupported)
		if len(scopes) == 0 {
			scopes = normalizeScopes(discovery.AuthorizationServer.ScopesSupported)
		}
		return s.repository.SaveClientConfiguration(ctx, &ClientConfiguration{
			ConnectionID: connectionID, UserID: caller.UserID, TenantID: caller.TenantID,
			Issuer: discovery.AuthorizationServer.Issuer, ClientIDCipher: clientIDCipher,
			ClientSecretCipher: clientSecretCipher, Scopes: scopes,
		})
	})
}

// BeginWithDynamicRegistration provisions a public OAuth client when the connection has no manual
// client configuration, then starts the browser authorization-code flow.
func (s *Service) BeginWithDynamicRegistration(ctx context.Context, connectionID uuid.UUID, redirectURI string) (*BeginResult, error) {
	if err := validateRedirectURI(redirectURI); err != nil {
		return nil, err
	}
	if err := s.ensureClient(ctx, connectionID, redirectURI); err != nil {
		return nil, err
	}
	return s.Begin(ctx, connectionID, redirectURI)
}

func (s *Service) register(ctx context.Context, discovery *Discovery, redirectURI string) (*registrationResponse, error) {
	endpoint := discovery.AuthorizationServer.RegistrationEndpoint
	if endpoint == "" {
		return nil, errors.New("authorization server does not support dynamic client registration")
	}
	if err := validateEndpoint(endpoint); err != nil {
		return nil, fmt.Errorf("invalid registration endpoint: %w", err)
	}
	authMethod, err := chooseRegistrationAuthMethod(discovery.AuthorizationServer.TokenAuthMethods)
	if err != nil {
		return nil, err
	}
	scopes := discovery.Resource.ScopesSupported
	if len(scopes) == 0 {
		scopes = discovery.AuthorizationServer.ScopesSupported
	}
	payload, err := json.Marshal(registrationRequest{
		ClientName: "DonkeyWork Vault MCP Gateway", RedirectURIs: []string{redirectURI},
		GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"},
		TokenEndpointAuthMethod: authMethod, Scope: strings.Join(normalizeScopes(scopes), " "), ApplicationType: "web",
	})
	if err != nil {
		return nil, err //coverage:ignore fixed registration request contains only JSON-safe values
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err //coverage:ignore endpoint and method were validated before constructing this request
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "donkeywork-vault")
	response, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OAuth client registration: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxMetadataBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxMetadataBytes {
		return nil, errors.New("OAuth client registration response is too large")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("OAuth client registration returned HTTP %d", response.StatusCode)
	}
	var registered registrationResponse
	if err := json.Unmarshal(body, &registered); err != nil {
		return nil, errors.New("OAuth client registration response is not valid JSON")
	}
	if registered.ClientID == "" {
		return nil, errors.New("OAuth client registration response omits client_id")
	}
	if registered.TokenEndpointAuthMethod != authMethod {
		return nil, errors.New("OAuth client registration returned an unexpected token authentication method")
	}
	if !slices.Contains(registered.RedirectURIs, redirectURI) {
		return nil, errors.New("OAuth client registration response omits the callback redirect URI")
	}
	if !slices.Contains(registered.GrantTypes, "authorization_code") || !slices.Contains(registered.ResponseTypes, "code") {
		return nil, errors.New("OAuth client registration response omits the authorization code flow")
	}
	if authMethod != "none" && registered.ClientSecret == "" {
		return nil, errors.New("OAuth client registration response omits client_secret")
	}
	return &registered, nil
}

func chooseRegistrationAuthMethod(supported []string) (string, error) {
	if len(supported) == 0 || slices.Contains(supported, "none") {
		return "none", nil
	}
	for _, method := range []string{"client_secret_post", "client_secret_basic"} {
		if slices.Contains(supported, method) {
			return method, nil
		}
	}
	return "", errors.New("authorization server supports no usable dynamic client authentication method")
}

func (s *Service) exchange(ctx context.Context, config *ConnectionOAuth, endpoint, authMethod string, values url.Values) (*tokenResponse, error) {
	if err := validateEndpoint(endpoint); err != nil {
		return nil, err
	}
	clientID, err := s.cipher.DecryptToString(config.ClientIDCipher)
	if err != nil {
		return nil, err
	}
	values.Set("client_id", clientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	if authMethod != "none" {
		clientSecret, err := s.cipher.DecryptToString(config.ClientSecretCipher)
		if err != nil {
			return nil, err
		}
		if authMethod == "client_secret_basic" {
			req.SetBasicAuth(clientID, clientSecret)
		} else {
			values.Set("client_secret", clientSecret)
			req.Body = io.NopCloser(strings.NewReader(values.Encode()))
			req.ContentLength = int64(len(values.Encode()))
		}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "donkeywork-vault")
	response, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OAuth token request: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxMetadataBytes))
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("OAuth token request returned HTTP %d", response.StatusCode)
	}
	var parsed tokenResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, errors.New("OAuth token response is not valid JSON")
	}
	if parsed.AccessToken == "" {
		return nil, errors.New("OAuth token response omits access_token")
	}
	if parsed.TokenType == "" {
		parsed.TokenType = "Bearer"
	}
	if !strings.EqualFold(parsed.TokenType, "Bearer") {
		return nil, fmt.Errorf("unsupported OAuth token type %q", parsed.TokenType)
	}
	parsed.TokenType = "Bearer"
	parsed.Scopes = strings.Fields(parsed.Scope)
	return &parsed, nil
}

func (s *Service) encryptResponse(connectionID, userID, tenantID uuid.UUID, resource, issuer, authorizationEndpoint, tokenEndpoint, authMethod string, fallbackScopes []string, response *tokenResponse) (*Authorization, *Token, error) {
	accessCipher, err := s.cipher.EncryptString(response.AccessToken)
	if err != nil {
		return nil, nil, err
	}
	var refreshCipher []byte
	if response.RefreshToken != "" {
		refreshCipher, err = s.cipher.EncryptString(response.RefreshToken)
		if err != nil {
			return nil, nil, err
		}
	}
	var expiresAt *time.Time
	if response.ExpiresIn > 0 {
		expires := s.now().UTC().Add(time.Duration(response.ExpiresIn) * time.Second)
		expiresAt = &expires
	}
	scopes := response.Scopes
	if len(scopes) == 0 {
		scopes = slices.Clone(fallbackScopes)
	}
	authorization := &Authorization{
		ConnectionID: connectionID, UserID: userID, TenantID: tenantID,
		Resource: resource, Issuer: issuer, AuthorizationEndpoint: authorizationEndpoint,
		TokenEndpoint: tokenEndpoint, TokenAuthMethod: authMethod,
		AccessTokenCipher: accessCipher, RefreshTokenCipher: refreshCipher,
		TokenType: "Bearer", Scopes: scopes, ExpiresAt: expiresAt, LastRefreshedAt: s.now().UTC(),
	}
	return authorization, &Token{AccessToken: response.AccessToken, TokenType: "Bearer", Scopes: slices.Clone(scopes), ExpiresAt: expiresAt}, nil
}

func (s *Service) decryptToken(authorization *Authorization) (*Token, error) {
	accessToken, err := s.cipher.DecryptToString(authorization.AccessTokenCipher)
	if err != nil {
		return nil, err
	}
	return &Token{AccessToken: accessToken, TokenType: "Bearer", Scopes: slices.Clone(authorization.Scopes), ExpiresAt: authorization.ExpiresAt}, nil
}

func (s *Service) getJSON(ctx context.Context, endpoint string, target interface{}) error {
	if err := validateEndpoint(endpoint); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err //coverage:ignore endpoint and method were validated before constructing this request
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "donkeywork-vault")
	response, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("metadata endpoint returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxMetadataBytes))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode metadata: %w", err)
	}
	return nil
}

func protectedResourceMetadataURL(resource string) (string, error) {
	parsed, err := url.Parse(resource)
	if err != nil {
		return "", err
	}
	path := strings.TrimSuffix(parsed.EscapedPath(), "/")
	parsed.Path = "/.well-known/oauth-protected-resource" + path
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func authorizationServerMetadataURL(issuer string) (string, error) {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return "", err
	}
	path := strings.TrimSuffix(parsed.EscapedPath(), "/")
	parsed.Path = "/.well-known/oauth-authorization-server" + path
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func selectIssuer(configured string, advertised []string) (string, error) {
	if configured != "" {
		if len(advertised) > 0 && !slices.Contains(advertised, configured) {
			return "", fmt.Errorf("%w: configured issuer is not advertised by resource", ErrBindingMismatch)
		}
		if err := validateEndpoint(configured); err != nil {
			return "", fmt.Errorf("invalid issuer: %w", err)
		}
		return configured, nil
	}
	if len(advertised) == 0 {
		return "", errors.New("protected resource metadata advertises no authorization server")
	}
	if err := validateEndpoint(advertised[0]); err != nil {
		return "", fmt.Errorf("invalid issuer: %w", err)
	}
	return advertised[0], nil
}

func chooseTokenAuthMethod(supported []string, hasSecret bool) (string, error) {
	if len(supported) == 0 {
		if hasSecret {
			return "client_secret_basic", nil
		}
		return "none", nil
	}
	if hasSecret {
		for _, method := range []string{"client_secret_basic", "client_secret_post"} {
			if slices.Contains(supported, method) {
				return method, nil
			}
		}
	} else if slices.Contains(supported, "none") {
		return "none", nil
	}
	return "", errors.New("authorization server and configured client share no supported token authentication method")
}

func validateEndpoint(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if parsed.User != nil || parsed.Fragment != "" || parsed.Hostname() == "" {
		return errors.New("URL must have a host and must not contain credentials or a fragment")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname()) {
		return nil
	}
	return errors.New("URL must use HTTPS (HTTP is allowed only for loopback hosts)")
}

func validateRedirectURI(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || parsed.Fragment != "" {
		return errors.New("invalid OAuth redirect URI")
	}
	if parsed.Scheme != "https" && (parsed.Scheme != "http" || !isLoopbackHost(parsed.Hostname())) {
		return errors.New("OAuth redirect URI must use HTTPS (HTTP is allowed only for loopback hosts)")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func normalizeScopes(scopes []string) []string {
	result := make([]string, 0, len(scopes))
	seen := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope != "" && !seen[scope] {
			seen[scope] = true
			result = append(result, scope)
		}
	}
	return result
}

type connectionLocks struct {
	mu      sync.Mutex
	entries map[uuid.UUID]*lockEntry
}

type lockEntry struct {
	mu   sync.Mutex
	refs int
}

func (l *connectionLocks) lock(id uuid.UUID) func() {
	l.mu.Lock()
	entry := l.entries[id]
	if entry == nil {
		entry = &lockEntry{}
		l.entries[id] = entry
	}
	entry.refs++
	l.mu.Unlock()
	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		l.mu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(l.entries, id)
		}
		l.mu.Unlock()
	}
}
