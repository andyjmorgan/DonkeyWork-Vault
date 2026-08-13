package mcpoauth

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/store"
	"donkeywork.dev/vault-server/internal/store/memstore"
)

func TestStoreRepositoryRoundTrip(t *testing.T) {
	ctx := context.Background()
	memory := memstore.New()
	repository := NewStoreRepository(memory)
	userID, tenantID, connectionID := uuid.New(), uuid.New(), uuid.New()
	connection := &store.MCPConnection{
		ID: connectionID, UserID: userID, TenantID: tenantID, Slug: "acme", Name: "Acme",
		UpstreamURL: "https://mcp.example.com/rpc", AuthMode: "oauth", AuditMode: "redacted",
	}
	if err := memory.InsertMCPConnection(ctx, connection); err != nil {
		t.Fatal(err)
	}
	issuer := "https://idp.example.com"
	client := &store.MCPOAuthAuthorization{
		UserID: userID, TenantID: tenantID, ConnectionID: connectionID, IssuerURL: &issuer,
		ClientIDCipher: []byte("client"), ClientSecretCipher: []byte("secret"), Scopes: []string{"read"},
	}
	if err := memory.InsertMCPOAuthAuthorization(ctx, client); err != nil {
		t.Fatal(err)
	}

	configuration, err := repository.GetConnectionOAuth(ctx, userID, connectionID)
	if err != nil {
		t.Fatal(err)
	}
	if configuration.Resource != connection.UpstreamURL || configuration.Issuer != issuer || configuration.UserID != userID || configuration.TenantID != tenantID {
		t.Fatalf("unexpected configuration: %+v", configuration)
	}
	if got, err := repository.GetConnectionOAuth(ctx, uuid.New(), connectionID); err != nil || got != nil {
		t.Fatalf("cross-owner configuration = %+v, %v", got, err)
	}

	expires := time.Now().UTC().Add(time.Minute)
	state := &State{
		State: "state", ConnectionID: connectionID, UserID: userID, TenantID: tenantID,
		CodeVerifier: "verifier", RedirectURI: "https://vault.example/callback",
		Resource: connection.UpstreamURL, Issuer: issuer,
		AuthorizationEndpoint: issuer + "/authorize", TokenEndpoint: issuer + "/token",
		TokenAuthMethod: "client_secret_basic", Scopes: []string{"read"}, ExpiresAt: expires,
	}
	if err := repository.SaveState(ctx, state); err != nil {
		t.Fatal(err)
	}
	claimed, err := repository.ClaimState(ctx, "state")
	if err != nil {
		t.Fatal(err)
	}
	if claimed == nil || claimed.UserID != userID || claimed.TenantID != tenantID || claimed.TokenAuthMethod != "client_secret_basic" || claimed.AuthorizationEndpoint != issuer+"/authorize" {
		t.Fatalf("unexpected claimed state: %+v", claimed)
	}
	if claimedAgain, err := repository.ClaimState(ctx, "state"); err != nil || claimedAgain != nil {
		t.Fatalf("replayed state = %+v, %v", claimedAgain, err)
	}

	lastRefreshed := time.Now().UTC()
	authorization := &Authorization{
		ConnectionID: connectionID, UserID: userID, TenantID: tenantID,
		Resource: connection.UpstreamURL, Issuer: issuer,
		AuthorizationEndpoint: issuer + "/authorize", TokenEndpoint: issuer + "/token",
		TokenAuthMethod: "client_secret_basic", AccessTokenCipher: []byte("access"),
		RefreshTokenCipher: []byte("refresh"), TokenType: "Bearer", Scopes: []string{"read"},
		ExpiresAt: &expires, LastRefreshedAt: lastRefreshed,
	}
	if err := repository.UpsertAuthorization(ctx, authorization); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.GetAuthorization(ctx, userID, connectionID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.TokenAuthMethod != "client_secret_basic" || string(loaded.AccessTokenCipher) != "access" || !loaded.LastRefreshedAt.Equal(lastRefreshed) {
		t.Fatalf("unexpected authorization: %+v", loaded)
	}
	if loaded, err := repository.GetAuthorization(ctx, uuid.New(), connectionID); err != nil || loaded != nil {
		t.Fatalf("cross-owner authorization = %+v, %v", loaded, err)
	}
}

func TestStoreRepositoryClientConfiguration(t *testing.T) {
	ctx := context.Background()
	memory := memstore.New()
	repository := NewStoreRepository(memory)
	userID, tenantID, connectionID := uuid.New(), uuid.New(), uuid.New()
	connection := &store.MCPConnection{ID: connectionID, UserID: userID, TenantID: tenantID, UpstreamURL: "https://mcp.example.com"}
	if err := memory.InsertMCPConnection(ctx, connection); err != nil {
		t.Fatal(err)
	}
	configuration := &ClientConfiguration{
		ConnectionID: connectionID, UserID: userID, TenantID: tenantID,
		Issuer: "https://idp.example.com", ClientIDCipher: []byte("client"), ClientSecretCipher: []byte("secret"), Scopes: []string{"read"},
	}
	if err := repository.SaveClientConfiguration(ctx, configuration); err != nil {
		t.Fatal(err)
	}
	row, err := memory.GetMCPOAuthAuthorization(ctx, userID, connectionID)
	if err != nil || row == nil || string(row.ClientIDCipher) != "client" {
		t.Fatalf("inserted row=%+v err=%v", row, err)
	}
	access, refresh, tokenEndpoint := "test-access", "test-refresh", "https://idp.example.com/token" //nolint:gosec // G101: inert encrypted fixture values
	row.AccessTokenCipher, row.RefreshTokenCipher, row.TokenEndpoint = []byte(access), []byte(refresh), &tokenEndpoint
	if updated, err := memory.UpdateMCPOAuthAuthorization(ctx, row); err != nil || !updated {
		t.Fatalf("seed tokens = %v, %v", updated, err)
	}
	configuration.ClientIDCipher = []byte("replacement")
	if err := repository.SaveClientConfiguration(ctx, configuration); err != nil {
		t.Fatal(err)
	}
	row, _ = memory.GetMCPOAuthAuthorization(ctx, userID, connectionID)
	if string(row.ClientIDCipher) != "replacement" || len(row.AccessTokenCipher) != 0 || len(row.RefreshTokenCipher) != 0 || row.TokenEndpoint != nil {
		t.Fatalf("updated row retained stale tokens: %+v", row)
	}

	configuration.TenantID = uuid.New()
	if err := repository.SaveClientConfiguration(ctx, configuration); err == nil {
		t.Fatal("expected tenant ownership error")
	}
}

func TestStoreRepositoryErrors(t *testing.T) {
	ctx := context.Background()
	memory := memstore.New()
	repository := NewStoreRepository(memory)
	userID, tenantID, connectionID := uuid.New(), uuid.New(), uuid.New()

	memory.FailNext = errors.New("database failed")
	if _, err := repository.GetConnectionOAuth(ctx, userID, connectionID); err == nil {
		t.Fatal("expected connection lookup error")
	}
	memory.FailNext = errors.New("database failed")
	if err := repository.SaveClientConfiguration(ctx, &ClientConfiguration{UserID: userID, ConnectionID: connectionID}); err == nil {
		t.Fatal("expected client connection lookup error")
	}
	connection := &store.MCPConnection{ID: connectionID, UserID: userID, TenantID: tenantID, UpstreamURL: "https://mcp.example.com"}
	if err := memory.InsertMCPConnection(ctx, connection); err != nil {
		t.Fatal(err)
	}
	memory.FailNext = errors.New("database failed")
	if _, err := repository.GetConnectionOAuth(ctx, userID, connectionID); err == nil {
		t.Fatal("expected authorization lookup error")
	}

	memory.FailNext = errors.New("database failed")
	if err := repository.SaveState(ctx, &State{}); err == nil {
		t.Fatal("expected state save error")
	}
	memory.FailNext = errors.New("database failed")
	if _, err := repository.ClaimState(ctx, "state"); err == nil {
		t.Fatal("expected state claim error")
	}
	memory.FailNext = errors.New("database failed")
	if _, err := repository.GetAuthorization(ctx, userID, connectionID); err == nil {
		t.Fatal("expected authorization read error")
	}
	memory.FailNext = errors.New("database failed")
	if err := repository.UpsertAuthorization(ctx, &Authorization{UserID: userID, ConnectionID: connectionID}); err == nil {
		t.Fatal("expected authorization upsert lookup error")
	}

	if err := repository.UpsertAuthorization(ctx, &Authorization{UserID: userID, TenantID: tenantID, ConnectionID: connectionID}); err == nil {
		t.Fatal("expected missing client config error")
	}

	issuer := "https://idp.example.com"
	client := &store.MCPOAuthAuthorization{
		UserID: userID, TenantID: tenantID, ConnectionID: connectionID, IssuerURL: &issuer,
		ClientIDCipher: []byte("client"),
	}
	if err := memory.InsertMCPOAuthAuthorization(ctx, client); err != nil {
		t.Fatal(err)
	}
	memory.FailNext = errors.New("database failed")
	if err := repository.UpsertAuthorization(ctx, &Authorization{UserID: userID, TenantID: tenantID, ConnectionID: connectionID}); err == nil {
		t.Fatal("expected update error")
	}
	if deleted, err := memory.DeleteMCPOAuthAuthorization(ctx, userID, connectionID); err != nil || !deleted {
		t.Fatalf("delete client = %v, %v", deleted, err)
	}
	if err := memory.InsertMCPOAuthAuthorization(ctx, client); err != nil {
		t.Fatal(err)
	}
	client.ID = uuid.New()
	if deleted, err := memory.DeleteMCPOAuthAuthorization(ctx, userID, connectionID); err != nil || !deleted {
		t.Fatalf("delete client = %v, %v", deleted, err)
	}
	if err := repository.UpsertAuthorization(ctx, &Authorization{UserID: userID, TenantID: tenantID, ConnectionID: connectionID}); err == nil {
		t.Fatal("expected missing client config error after deletion")
	}
}

func TestAuthorizationFromStoreDefaults(t *testing.T) {
	now := time.Now().UTC()
	value := "value"
	authorization := authorizationFromStore(&store.MCPOAuthAuthorization{
		ConnectionID: uuid.New(), CreatedAt: now, Resource: &value,
	})
	if authorization.LastRefreshedAt != now || authorization.Resource != value || dereference(nil) != "" {
		t.Fatalf("unexpected authorization defaults: %+v", authorization)
	}
}

func TestStoreRepositoryStatus(t *testing.T) {
	memory := memstore.New()
	userID, tenantID, connectionID := uuid.New(), uuid.New(), uuid.New()
	ctx := context.Background()
	connection := &store.MCPConnection{ID: connectionID, UserID: userID, TenantID: tenantID, UpstreamURL: "https://mcp.example", Enabled: true}
	if err := memory.InsertMCPConnection(ctx, connection); err != nil {
		t.Fatal(err)
	}
	repository := NewStoreRepository(memory)

	status, err := repository.GetStatus(ctx, userID, connectionID)
	if err != nil || status == nil || status.ConnectionID != connectionID || status.Configured || status.Authorized || status.Resource != "" {
		t.Fatalf("unconfigured status: %+v, %v", status, err)
	}
	issuer := "https://issuer.example"
	row := &store.MCPOAuthAuthorization{
		UserID: userID, TenantID: tenantID, ConnectionID: connectionID, IssuerURL: &issuer,
		ClientIDCipher: []byte("client"), Scopes: []string{"read", "write"},
	}
	if err := memory.InsertMCPOAuthAuthorization(ctx, row); err != nil {
		t.Fatal(err)
	}
	status, err = repository.GetStatus(ctx, userID, connectionID)
	if err != nil || status == nil || !status.Configured || status.Authorized || status.Issuer != issuer || status.Resource != connection.UpstreamURL || !slices.Equal(status.Scopes, row.Scopes) {
		t.Fatalf("configured status: %+v, %v", status, err)
	}
	status.Scopes[0] = "changed"
	stored, _ := memory.GetMCPOAuthAuthorization(ctx, userID, connectionID)
	if stored.Scopes[0] != "read" {
		t.Fatal("status scopes alias stored scopes")
	}
	now := time.Now().UTC()
	expiresAt := now.Add(time.Hour)
	resource := "https://resource.example"
	row.Resource, row.AccessTokenCipher, row.ExpiresAt, row.LastRefreshedAt = &resource, []byte("token"), &expiresAt, &now
	if updated, updateErr := memory.UpdateMCPOAuthAuthorization(ctx, row); updateErr != nil || !updated {
		t.Fatalf("update authorization: %v, %v", updated, updateErr)
	}
	status, err = repository.GetStatus(ctx, userID, connectionID)
	if err != nil || status == nil || !status.Authorized || status.Resource != resource || status.ExpiresAt == nil || !status.ExpiresAt.Equal(expiresAt) || status.LastRefreshedAt == nil || !status.LastRefreshedAt.Equal(now) {
		t.Fatalf("authorized status: %+v, %v", status, err)
	}
	if hidden, hiddenErr := repository.GetStatus(ctx, uuid.New(), connectionID); hiddenErr != nil || hidden != nil {
		t.Fatalf("cross-owner status: %+v, %v", hidden, hiddenErr)
	}
	if missing, missingErr := repository.GetStatus(ctx, userID, uuid.New()); missingErr != nil || missing != nil {
		t.Fatalf("missing status: %+v, %v", missing, missingErr)
	}
	memory.FailNext = errors.New("connection lookup failed")
	if _, err := repository.GetStatus(ctx, userID, connectionID); err == nil {
		t.Fatal("connection lookup error not returned")
	}
	memory.FailNext = errors.New("authorization lookup failed")
	if _, err := repository.GetStatus(ctx, userID, connectionID); err == nil {
		t.Fatal("authorization lookup error not returned")
	}
}
