package httpapi

import (
	"reflect"
	"testing"
)

func TestVaultScopesFor(t *testing.T) {
	web, cli := "vault-web", "vault-cli"
	cases := []struct {
		name      string
		clientID  string
		audiences []string
		want      []string
	}{
		{"web client full", web, []string{web}, webVaultScopes},
		{"cli client subset", cli, []string{web}, cliVaultScopes},
		{"cli without web audience", cli, []string{cli}, nil},
		{"unknown client", "other", []string{"other"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := vaultScopesFor(c.clientID, c.audiences, web, cli); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %v want %v", got, c.want)
			}
		})
	}
}

func TestClientIDFromClaims(t *testing.T) {
	if got := clientIDFromClaims("azp1", "cid", []string{"a"}); got != "azp1" {
		t.Fatalf("azp precedence: %s", got)
	}
	if got := clientIDFromClaims("", "cid", []string{"a", "b"}); got != "cid" {
		t.Fatalf("client_id fallback: %s", got)
	}
	if got := clientIDFromClaims("", "", []string{"sole"}); got != "sole" {
		t.Fatalf("sole audience: %s", got)
	}
	if got := clientIDFromClaims("", "", []string{"a", "b"}); got != "" {
		t.Fatalf("ambiguous audience: %s", got)
	}
}
