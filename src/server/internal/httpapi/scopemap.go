package httpapi

// Vault scope sets granted to interactive OIDC callers, by requesting OAuth client. A web/portal
// user is the trusted human/admin (full set incl. audit); the CLI (device authorization) gets the
// operational subset.
var (
	webVaultScopes = []string{"vault:read", "vault:readwrite", "vault:audit"}
	cliVaultScopes = []string{"vault:read", "vault:readwrite"}
)

// vaultScopesFor maps a validated token's client identity to the vault scopes it carries. A CLI
// token (its client id is the CLI client, and it was issued for the web audience) gets the CLI set;
// a web token gets the full set; anything else gets none (and is denied at the scope gate).
func vaultScopesFor(clientID string, audiences []string, webClientID, cliClientID string) []string {
	if clientID == cliClientID && cliClientID != "" && contains(audiences, webClientID) {
		return cliVaultScopes
	}
	if clientID == webClientID && webClientID != "" {
		return webVaultScopes
	}
	return nil
}

// clientIDFromClaims resolves the requesting OAuth client: Keycloak's azp, then client_id, then a
// sole audience.
func clientIDFromClaims(azp, clientID string, audiences []string) string {
	if azp != "" {
		return azp
	}
	if clientID != "" {
		return clientID
	}
	if len(audiences) == 1 {
		return audiences[0]
	}
	return ""
}

func contains(s []string, v string) bool {
	if v == "" {
		return false
	}
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
