// internal/httpclient/http.go — shared HTTP transport for all integrations.
//
// Improvements in this revision:
//   - DoGetCtx / DoPostCtx accept a context.Context so callers can honour
//     request cancellation (e.g. browser disconnect) and avoid burning API
//     quota on abandoned scans.
//   - DoGet / DoPost are kept for backward compatibility; they delegate to
//     the context-aware variants using context.Background().
package httpclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is the shared HTTP client used by every integration.
// 15-second timeout is generous enough for slow threat-intel APIs.
// The context passed to DoGetCtx / DoPostCtx can enforce a tighter deadline.
var Client = &http.Client{Timeout: 15 * time.Second}

// DoGetCtx performs a GET request with the given headers, honouring ctx for
// cancellation. Returns the response body on HTTP 200, or an error otherwise.
func DoGetCtx(ctx context.Context, rawURL string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "iocscan/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, rawURL)
	}
	return io.ReadAll(resp.Body)
}

// DoPostCtx performs a POST with an application/x-www-form-urlencoded body,
// honouring ctx for cancellation.
func DoPostCtx(ctx context.Context, rawURL, body string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "iocscan/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, rawURL)
	}
	return io.ReadAll(resp.Body)
}

// DoGet is the context-free variant of DoGetCtx kept for backward compatibility.
// New integrations should prefer DoGetCtx.
func DoGet(rawURL string, headers map[string]string) ([]byte, error) {
	return DoGetCtx(context.Background(), rawURL, headers)
}

// DoPost is the context-free variant of DoPostCtx kept for backward compatibility.
// New integrations should prefer DoPostCtx.
func DoPost(rawURL, body string, headers map[string]string) ([]byte, error) {
	return DoPostCtx(context.Background(), rawURL, body, headers)
}
