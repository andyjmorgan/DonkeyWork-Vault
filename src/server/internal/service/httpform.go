package service

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// postForm issues an application/x-www-form-urlencoded POST and returns the status and body. The
// client should carry the otelhttp transport in production, so the outbound token/refresh exchange
// appears as a child span of the request.
func postForm(ctx context.Context, client *http.Client, endpoint string, form url.Values) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "donkeywork-vault")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	// Cap the provider response: a token endpoint JSON body is small; an unbounded read of a
	// hostile/compromised endpoint could OOM the process.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes))
	return resp.StatusCode, body, err
}

// maxTokenResponseBytes bounds an OAuth token/userinfo response body (1 MiB is far above any real one).
const maxTokenResponseBytes = 1 << 20

func httpOK(status int) bool { return status >= 200 && status < 300 }
