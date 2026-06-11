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
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, body, err
}

func httpOK(status int) bool { return status >= 200 && status < 300 }
