package oauthdevice

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"donkeywork.dev/vault-cli/internal/restclient"
)

type Discovery struct {
	Issuer                      string `json:"issuer"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
}

type DeviceStart struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
	CodeVerifier            string `json:"-"`
}

type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type Claims struct {
	Subject           string
	Email             string
	PreferredUsername string
}

func Discover(authority string) (*Discovery, error) {
	u := strings.TrimRight(authority, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	var d Discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, err
	}
	if d.DeviceAuthorizationEndpoint == "" || d.TokenEndpoint == "" {
		return nil, fmt.Errorf("issuer does not advertise OAuth device authorization")
	}
	return &d, nil
}

func Start(d *Discovery, clientID, scopes string) (*DeviceStart, error) {
	verifier, challenge, err := pkce()
	if err != nil {
		return nil, err //coverage:ignore pkce only fails if crypto/rand fails, which never happens in practice
	}
	body, status, err := restclient.PostForm(d.DeviceAuthorizationEndpoint, map[string]string{
		"client_id":             clientID,
		"scope":                 scopes,
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
	})
	if err != nil {
		return nil, err
	}
	if status/100 != 2 {
		return nil, oauthError("start device authorization", status, body)
	}
	var start DeviceStart
	if err := json.Unmarshal(body, &start); err != nil {
		return nil, err
	}
	start.CodeVerifier = verifier
	if start.Interval <= 0 {
		start.Interval = 5
	}
	return &start, nil
}

func Poll(d *Discovery, clientID string, start *DeviceStart, notify func(time.Duration)) (*TokenResponse, error) {
	deadline := time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)
	interval := time.Duration(start.Interval) * time.Second
	for {
		if notify != nil {
			notify(interval)
		}
		time.Sleep(interval)
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("device authorization expired")
		}
		tok, err := token(d.TokenEndpoint, map[string]string{
			"grant_type":    "urn:ietf:params:oauth:grant-type:device_code",
			"client_id":     clientID,
			"device_code":   start.DeviceCode,
			"code_verifier": start.CodeVerifier,
		})
		if err == nil {
			return tok, nil
		}
		var oe oauthErr
		if !errors.As(err, &oe) {
			return nil, err
		}
		switch oe.Code {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		default:
			return nil, err
		}
	}
}

func Refresh(tokenEndpoint, clientID, refreshToken string) (*TokenResponse, error) {
	return token(tokenEndpoint, map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     clientID,
		"refresh_token": refreshToken,
	})
}

func DecodeClaims(accessToken string) Claims {
	parts := strings.Split(accessToken, ".")
	if len(parts) < 2 {
		return Claims{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}
	}
	var raw struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
	}
	if json.Unmarshal(payload, &raw) != nil {
		return Claims{}
	}
	return Claims{Subject: raw.Sub, Email: raw.Email, PreferredUsername: raw.PreferredUsername}
}

func token(endpoint string, values map[string]string) (*TokenResponse, error) {
	body, status, err := restclient.PostForm(endpoint, values)
	if err != nil {
		return nil, err
	}
	if status/100 != 2 {
		return nil, oauthError("token request", status, body)
	}
	var tok TokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, err
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("token response missing access_token")
	}
	return &tok, nil
}

type oauthErr struct {
	Code        string
	Description string
	Status      int
}

func (e oauthErr) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Description)
	}
	return e.Code
}

func oauthError(op string, status int, body []byte) error {
	var e TokenResponse
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		return oauthErr{Code: e.Error, Description: e.ErrorDescription, Status: status}
	}
	return fmt.Errorf("%s: HTTP %d", op, status)
}

func pkce() (verifier string, challenge string, err error) {
	raw := make([]byte, 64)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err //coverage:ignore crypto/rand never fails in practice
	}
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}
