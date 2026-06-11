package contracts

import (
	"encoding/json"
	"fmt"
)

// CredentialKind is the discriminator that tells an agent how to use a stored secret. It is
// serialized as a snake_case string on both the API (JSON) and the entity (a text column), never as
// an integer — the wire form the CLI/SPA consume.
type CredentialKind string

const (
	// KindOpaque is the catch-all: the secret is opaque material, returned verbatim.
	KindOpaque CredentialKind = "opaque"
	// KindHeaderAPIKey is sent in an HTTP header: {header}: {prefix}{secret}.
	KindHeaderAPIKey CredentialKind = "header_api_key"
	// KindHTTPBasic is HTTP Basic: Authorization: Basic base64(username:secret).
	KindHTTPBasic CredentialKind = "http_basic"
	// KindUsernamePassword is a username+password login that is NOT sent as HTTP Basic.
	KindUsernamePassword CredentialKind = "username_password"
	// KindSSH is an SSH login: username + host; secret is the password or key.
	KindSSH CredentialKind = "ssh"
	// KindConnectionString means the whole connection string / DSN is the secret.
	KindConnectionString CredentialKind = "connection_string"
)

// CredentialKindFromWire maps a stored/text value to a CredentialKind, defaulting to opaque for any
// unknown or empty input.
func CredentialKindFromWire(s string) CredentialKind {
	switch CredentialKind(s) {
	case KindHeaderAPIKey, KindHTTPBasic, KindUsernamePassword, KindSSH, KindConnectionString:
		return CredentialKind(s)
	default:
		return KindOpaque
	}
}

// MarshalJSON always emits a known wire value (defaulting unknowns to opaque).
func (k CredentialKind) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(CredentialKindFromWire(string(k))))
}

// UnmarshalJSON accepts the snake_case wire form, defaulting unknowns to opaque.
func (k *CredentialKind) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("credential kind must be a string: %w", err)
	}
	*k = CredentialKindFromWire(s)
	return nil
}
