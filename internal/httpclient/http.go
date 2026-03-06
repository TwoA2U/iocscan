// internal/httpclient/http.go — shared HTTP transport for all packages.
//
// Kept in its own package so both utils/ and integrations/ can import it
// without creating an import cycle.
package httpclient

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is the shared HTTP client used by every integration.
// 15-second timeout is generous enough for slow threat-intel APIs.
var Client = &http.Client{Timeout: 15 * time.Second}

// DoGet performs a GET request with the given headers and returns the body.
func DoGet(rawURL string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
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

// DoPost performs a POST with an application/x-www-form-urlencoded body.
func DoPost(rawURL, body string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(body))
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
