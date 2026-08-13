// Package mcplegacy adapts stateless July 2026 requests to a session-era MCP upstream.
package mcplegacy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultProtocolVersion = "2025-06-18"
	defaultMaxBodyBytes    = int64(1 << 20)
	initializeRequestID    = "dwv-legacy-initialize"
)

// ErrorKind classifies adapter failures without retaining upstream payloads or credentials.
type ErrorKind string

const (
	// ErrorInvalidConfig means the adapter configuration is unusable.
	ErrorInvalidConfig ErrorKind = "invalid_config"
	// ErrorInvalidRequest means a downstream request cannot be represented for the legacy upstream.
	ErrorInvalidRequest ErrorKind = "invalid_request"
	// ErrorResponseTooLarge means a lifecycle response exceeded the configured inspection limit.
	ErrorResponseTooLarge ErrorKind = "response_too_large"
	// ErrorInitializeRejected means the upstream rejected initialize or initialized.
	ErrorInitializeRejected ErrorKind = "initialize_rejected"
	// ErrorInvalidInitialize means the upstream returned a malformed initialize response.
	ErrorInvalidInitialize ErrorKind = "invalid_initialize"
	// ErrorVersionMismatch means the upstream selected a different legacy protocol revision.
	ErrorVersionMismatch ErrorKind = "version_mismatch"
	// ErrorClosed means the adapter has been permanently closed.
	ErrorClosed ErrorKind = "closed"
	// ErrorTransport means an upstream request or response-body read failed.
	ErrorTransport ErrorKind = "transport"
	// ErrorObserver means lifecycle auditing failed and the operation was stopped.
	ErrorObserver ErrorKind = "observer"
)

// Error is an audit-safe adapter failure.
type Error struct {
	Kind ErrorKind
	err  error
}

// Error implements error without including upstream response content.
func (e *Error) Error() string { return "legacy MCP adapter: " + string(e.Kind) }

// Unwrap exposes transport and context errors where one exists.
func (e *Error) Unwrap() error { return e.err }

// IsErrorKind reports whether err is an adapter error of kind.
func IsErrorKind(err error, kind ErrorKind) bool {
	var target *Error
	return errors.As(err, &target) && target.Kind == kind
}

// Config defines one provider-neutral session-era upstream adapter.
type Config struct {
	Endpoint        string
	Client          *http.Client
	ProtocolVersion string
	ClientName      string
	ClientVersion   string
	MaxConcurrent   int
	MaxBodyBytes    int64
	IdleTimeout     time.Duration
}

// LifecycleDirection identifies which side sent an adapter-owned lifecycle message.
type LifecycleDirection string

const (
	// LifecycleToUpstream is a lifecycle request or notification sent to the legacy server.
	LifecycleToUpstream LifecycleDirection = "to_upstream"
	// LifecycleFromUpstream is a lifecycle response received from the legacy server.
	LifecycleFromUpstream LifecycleDirection = "from_upstream"
)

// LifecycleMessage is a detached, header-free copy of an adapter-owned JSON-RPC message.
type LifecycleMessage struct {
	Direction LifecycleDirection
	Method    string
	Body      []byte
}

// LifecycleObserver receives lifecycle messages created while serving one DoObserved call.
// It must return promptly. Returning an error stops the lifecycle before its next network send.
// The adapter never retains the observer or message body.
type LifecycleObserver func(LifecycleMessage) error

// Adapter owns one upstream legacy lifecycle while downstream requests remain stateless.
// It retains only protocol state; authorization and static credential headers are derived from
// every Do request and are never stored.
type Adapter struct {
	endpoint        string
	client          *http.Client
	protocolVersion string
	clientName      string
	clientVersion   string
	maxBodyBytes    int64
	idleTimeout     time.Duration
	permits         chan struct{}

	mu           sync.Mutex
	initialized  bool
	sessionID    string
	initializing chan struct{}
	initErr      error
	closed       bool
	active       int
	lastUsed     time.Time
}

// New creates a legacy adapter without contacting the upstream.
func New(config Config) (*Adapter, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || config.Client == nil {
		return nil, &Error{Kind: ErrorInvalidConfig, err: err}
	}
	if config.ProtocolVersion == "" {
		config.ProtocolVersion = defaultProtocolVersion
	}
	if config.ClientName == "" || config.ClientVersion == "" {
		return nil, &Error{Kind: ErrorInvalidConfig}
	}
	if config.MaxConcurrent <= 0 {
		config.MaxConcurrent = 8
	}
	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = defaultMaxBodyBytes
	}
	if config.IdleTimeout < 0 {
		return nil, &Error{Kind: ErrorInvalidConfig}
	}
	return &Adapter{
		endpoint: endpoint.String(), client: config.Client, protocolVersion: config.ProtocolVersion,
		clientName: config.ClientName, clientVersion: config.ClientVersion, maxBodyBytes: config.MaxBodyBytes,
		idleTimeout: config.IdleTimeout, permits: make(chan struct{}, config.MaxConcurrent),
	}, nil
}

// Do initializes the legacy lifecycle if necessary, translates one July request, and sends it.
// A request carrying a session is retried exactly once only after HTTP 404, which the legacy
// Streamable HTTP specification defines as rejection of a terminated session before acceptance.
func (a *Adapter) Do(ctx context.Context, request *http.Request) (*http.Response, error) {
	return a.DoObserved(ctx, request, nil)
}

// DoObserved behaves like Do and emits adapter-owned lifecycle JSON-RPC messages to observer.
// Operation messages remain the caller's responsibility to audit.
func (a *Adapter) DoObserved(ctx context.Context, request *http.Request, observer LifecycleObserver) (*http.Response, error) {
	if request == nil || request.Body == nil {
		return nil, &Error{Kind: ErrorInvalidRequest}
	}
	if err := a.acquire(ctx); err != nil {
		return nil, err
	}
	release := true
	defer func() {
		if release {
			a.release()
		}
	}()

	body, err := readBounded(request.Body, a.maxBodyBytes)
	if err != nil {
		if !IsErrorKind(err, ErrorResponseTooLarge) {
			return nil, &Error{Kind: ErrorInvalidRequest, err: err}
		}
		return nil, err
	}
	translated, err := translateRequestBody(body)
	if err != nil {
		return nil, err
	}
	if err := a.ensureInitialized(ctx, request.Header, observer); err != nil {
		return nil, err
	}

	for attempt := 0; attempt < 2; attempt++ {
		session := a.currentSession()
		upstream, err := a.operationRequest(ctx, request.Header, translated, session)
		if err != nil { //coverage:ignore endpoint and method were validated by New.
			return nil, &Error{Kind: ErrorInvalidRequest, err: err}
		}
		response, err := a.client.Do(upstream)
		if err != nil {
			return nil, &Error{Kind: ErrorTransport, err: err}
		}
		if attempt == 0 && invalidSessionResponse(response, session) {
			_ = response.Body.Close()
			a.invalidateSession(session)
			if err := a.ensureInitialized(ctx, request.Header, observer); err != nil {
				return nil, err
			}
			continue
		}
		a.touch()
		response.Body = &releaseBody{ReadCloser: response.Body, release: a.release}
		release = false
		return response, nil
	}
	return nil, &Error{Kind: ErrorInitializeRejected} //coverage:ignore loop returns on its second attempt.
}

// ExpireIdle forgets an unused lifecycle so the next request reinitializes. It does not send
// DELETE because no current authorization material is retained by the adapter.
func (a *Adapter) ExpireIdle(now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.idleTimeout == 0 || a.active != 0 || !a.initialized || now.Sub(a.lastUsed) < a.idleTimeout {
		return false
	}
	a.initialized, a.sessionID, a.initErr = false, "", nil
	return true
}

// Close prevents new work, waits for active response bodies to close, and sends a best-effort
// legacy DELETE using fresh headers from template. The adapter retains none of those headers.
func (a *Adapter) Close(ctx context.Context, template *http.Request) error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	a.mu.Unlock()

	acquired := 0
	for acquired < cap(a.permits) {
		select {
		case a.permits <- struct{}{}:
			acquired++
		case <-ctx.Done():
			for acquired > 0 {
				<-a.permits
				acquired--
			}
			return ctx.Err()
		}
	}
	defer func() {
		for acquired > 0 {
			<-a.permits
			acquired--
		}
	}()

	a.mu.Lock()
	session := a.sessionID
	a.initialized, a.sessionID = false, ""
	a.mu.Unlock()
	if session == "" || template == nil {
		return nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, a.endpoint, nil)
	if err != nil { //coverage:ignore endpoint was validated by New.
		return err
	}
	request.Header = legacyHeaders(template.Header, a.protocolVersion, session)
	response, err := a.client.Do(request)
	if err != nil {
		return &Error{Kind: ErrorTransport, err: err}
	}
	_ = response.Body.Close()
	return nil
}

func (a *Adapter) acquire(ctx context.Context) error {
	a.mu.Lock()
	closed := a.closed
	a.mu.Unlock()
	if closed {
		return &Error{Kind: ErrorClosed}
	}
	select {
	case a.permits <- struct{}{}:
		a.mu.Lock()
		if a.closed {
			a.mu.Unlock()
			<-a.permits
			return &Error{Kind: ErrorClosed}
		}
		a.active++
		a.mu.Unlock()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *Adapter) release() {
	a.mu.Lock()
	a.active--
	a.mu.Unlock()
	<-a.permits
}

func (a *Adapter) ensureInitialized(ctx context.Context, currentHeaders http.Header, observer LifecycleObserver) error {
	for {
		a.mu.Lock()
		if a.initialized {
			a.mu.Unlock()
			return nil
		}
		if a.initializing != nil {
			wait := a.initializing
			a.mu.Unlock()
			select {
			case <-wait:
				a.mu.Lock()
				err := a.initErr
				a.mu.Unlock()
				if err != nil {
					return err
				}
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		wait := make(chan struct{})
		a.initializing = wait
		a.mu.Unlock()

		session, err := a.initialize(ctx, currentHeaders, observer)
		a.mu.Lock()
		if err == nil {
			a.initialized, a.sessionID, a.lastUsed = true, session, time.Now()
		}
		a.initErr = err
		a.initializing = nil
		close(wait)
		a.mu.Unlock()
		return err
	}
}

func (a *Adapter) initialize(ctx context.Context, currentHeaders http.Header, observer LifecycleObserver) (string, error) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": initializeRequestID, "method": "initialize",
		"params": map[string]any{"protocolVersion": a.protocolVersion, "capabilities": map[string]any{},
			"clientInfo": map[string]string{"name": a.clientName, "version": a.clientVersion}},
	})
	if err != nil { //coverage:ignore fixed JSON values are always encodable.
		return "", &Error{Kind: ErrorInvalidInitialize, err: err}
	}
	if err := observeLifecycle(observer, LifecycleToUpstream, "initialize", body); err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(body))
	if err != nil { //coverage:ignore endpoint was validated by New.
		return "", &Error{Kind: ErrorInvalidConfig, err: err}
	}
	request.Header = legacyHeaders(currentHeaders, a.protocolVersion, "")
	response, err := a.client.Do(request)
	if err != nil {
		return "", &Error{Kind: ErrorTransport, err: err}
	}
	defer func() { _ = response.Body.Close() }()
	responseBody, err := readBounded(response.Body, a.maxBodyBytes)
	if err != nil {
		if !IsErrorKind(err, ErrorResponseTooLarge) {
			return "", &Error{Kind: ErrorTransport, err: err}
		}
		return "", err
	}
	if err := observeLifecycle(observer, LifecycleFromUpstream, "initialize", responseBody); err != nil {
		return "", err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", &Error{Kind: ErrorInitializeRejected}
	}
	if err := validateInitializeResponse(responseBody, a.protocolVersion); err != nil {
		return "", err
	}
	session := strings.TrimSpace(response.Header.Get("MCP-Session-Id"))
	if !validSessionID(session) {
		return "", &Error{Kind: ErrorInvalidInitialize}
	}

	notification, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if err != nil { //coverage:ignore endpoint was validated by New.
		return "", &Error{Kind: ErrorInvalidConfig, err: err}
	}
	if err := observeLifecycle(observer, LifecycleToUpstream, "notifications/initialized", []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)); err != nil {
		return "", err
	}
	notification.Header = legacyHeaders(currentHeaders, a.protocolVersion, session)
	notificationResponse, err := a.client.Do(notification)
	if err != nil {
		return "", &Error{Kind: ErrorTransport, err: err}
	}
	_ = notificationResponse.Body.Close()
	if notificationResponse.StatusCode < 200 || notificationResponse.StatusCode > 299 {
		return "", &Error{Kind: ErrorInitializeRejected}
	}
	return session, nil
}

func observeLifecycle(observer LifecycleObserver, direction LifecycleDirection, method string, body []byte) error {
	if observer == nil {
		return nil
	}
	if err := observer(LifecycleMessage{Direction: direction, Method: method, Body: bytes.Clone(body)}); err != nil {
		return &Error{Kind: ErrorObserver, err: err}
	}
	return nil
}

func (a *Adapter) operationRequest(ctx context.Context, headers http.Header, body []byte, session string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header = legacyHeaders(headers, a.protocolVersion, session)
	return request, nil
}

func (a *Adapter) currentSession() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessionID
}

func (a *Adapter) invalidateSession(observed string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.initialized && a.sessionID == observed {
		a.initialized, a.sessionID, a.initErr = false, "", nil
	}
}

func (a *Adapter) touch() {
	a.mu.Lock()
	a.lastUsed = time.Now()
	a.mu.Unlock()
}

func invalidSessionResponse(response *http.Response, sentSession string) bool {
	return sentSession != "" && response.StatusCode == http.StatusNotFound
}

func translateRequestBody(body []byte) ([]byte, error) {
	var object map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, &Error{Kind: ErrorInvalidRequest, err: err}
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, &Error{Kind: ErrorInvalidRequest, err: err}
	}
	if _, ok := object["method"]; !ok {
		return nil, &Error{Kind: ErrorInvalidRequest}
	}
	if rawParams, ok := object["params"]; ok {
		var params map[string]json.RawMessage
		if json.Unmarshal(rawParams, &params) != nil {
			return nil, &Error{Kind: ErrorInvalidRequest}
		}
		if rawMeta, ok := params["_meta"]; ok {
			var meta map[string]json.RawMessage
			if json.Unmarshal(rawMeta, &meta) != nil {
				return nil, &Error{Kind: ErrorInvalidRequest}
			}
			for _, key := range []string{
				"io.modelcontextprotocol/protocolVersion", "io.modelcontextprotocol/clientInfo",
				"io.modelcontextprotocol/clientCapabilities", "io.modelcontextprotocol/logLevel",
			} {
				delete(meta, key)
			}
			if len(meta) == 0 {
				delete(params, "_meta")
			} else {
				params["_meta"], _ = json.Marshal(meta)
			}
			object["params"], _ = json.Marshal(params)
		}
	}
	translated, err := json.Marshal(object)
	if err != nil { //coverage:ignore object contains already-valid JSON values.
		return nil, &Error{Kind: ErrorInvalidRequest, err: err}
	}
	return translated, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing json.RawMessage
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}

func validateInitializeResponse(body []byte, protocolVersion string) error {
	var envelope struct {
		JSONRPC string `json:"jsonrpc"`
		ID      string `json:"id"`
		Result  *struct {
			ProtocolVersion string                     `json:"protocolVersion"`
			Capabilities    map[string]json.RawMessage `json:"capabilities"`
			ServerInfo      *struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"serverInfo"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&envelope); err != nil || ensureJSONEOF(decoder) != nil || envelope.JSONRPC != "2.0" || envelope.ID != initializeRequestID || envelope.Result == nil || len(envelope.Error) != 0 {
		return &Error{Kind: ErrorInvalidInitialize, err: err}
	}
	if envelope.Result.ProtocolVersion != protocolVersion {
		return &Error{Kind: ErrorVersionMismatch}
	}
	if envelope.Result.Capabilities == nil || envelope.Result.ServerInfo == nil || envelope.Result.ServerInfo.Name == "" || envelope.Result.ServerInfo.Version == "" {
		return &Error{Kind: ErrorInvalidInitialize}
	}
	return nil
}

func legacyHeaders(current http.Header, protocolVersion, session string) http.Header {
	headers := current.Clone()
	for name := range headers {
		lower := strings.ToLower(name)
		if lower == "mcp-method" || lower == "mcp-name" || strings.HasPrefix(lower, "mcp-param-") || lower == "mcp-session-id" || lower == "last-event-id" {
			headers.Del(name)
		}
	}
	headers.Set("Content-Type", "application/json")
	headers.Set("Accept", "application/json, text/event-stream")
	headers.Set("MCP-Protocol-Version", protocolVersion)
	if session != "" {
		headers.Set("MCP-Session-Id", session)
	}
	return headers
}

func validSessionID(session string) bool {
	if session == "" {
		return false
	}
	for index := 0; index < len(session); index++ {
		if session[index] < 0x21 || session[index] > 0x7e {
			return false
		}
	}
	return true
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, &Error{Kind: ErrorResponseTooLarge}
	}
	return body, nil
}

type releaseBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (body *releaseBody) Close() error {
	err := body.ReadCloser.Close()
	body.once.Do(body.release)
	return err
}
