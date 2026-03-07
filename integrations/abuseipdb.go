// integrations/abuseipdb.go — AbuseIPDB enrichment for IP addresses.
//
// API docs: https://docs.abuseipdb.com/#check-endpoint
//
// Endpoint: GET https://api.abuseipdb.com/api/v2/check
// Auth: Key header (required).
//
// This file owns:
//   - Raw API response type (abuseAPIResponse)
//   - Internal cleaned type (AbuseIPResult) used for caching
//   - Output type (IPAbuseIPDB) surfaced in IP scan results
//   - Fetch function (FetchAbuseIP)
//   - Mapping function (MapAbuseIPResult)
package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/TwoA2U/iocscan/internal/httpclient"
)

const abuseEndpoint = "https://api.abuseipdb.com/api/v2/check"

// ── Raw API response type ─────────────────────────────────────────────────────

// abuseAPIResponse is the raw envelope returned by AbuseIPDB.
type abuseAPIResponse struct {
	Data struct {
		IPAddress            string   `json:"ipAddress"`
		IsPublic             bool     `json:"isPublic"`
		IsWhitelisted        bool     `json:"isWhitelisted"`
		AbuseConfidenceScore int      `json:"abuseConfidenceScore"`
		CountryCode          string   `json:"countryCode"`
		ISP                  string   `json:"isp"`
		Hostnames            []string `json:"hostnames"`
		TotalReports         int      `json:"totalReports"`
		LastReportedAt       string   `json:"lastReportedAt"`
	} `json:"data"`
}

// ── Cleaned types ─────────────────────────────────────────────────────────────

// AbuseIPResult holds the full cleaned AbuseIPDB response, used for caching
// and as the source for geo data merged into IPGeo by the orchestrator.
type AbuseIPResult struct {
	IPAddress            string   `json:"ipAddress"`
	IsPublic             bool     `json:"isPublic"`
	IsWhitelisted        bool     `json:"isWhitelisted"`
	AbuseConfidenceScore int      `json:"abuseConfidenceScore"`
	CountryCode          string   `json:"countryCode"`
	ISP                  string   `json:"isp"`
	Hostnames            []string `json:"hostnames"`
	TotalReports         int      `json:"totalReports"`
	LastReportedAt       string   `json:"lastReportedAt"`
}

// IPAbuseIPDB holds the AbuseIPDB enrichment fields surfaced in an IP scan result.
// Error is non-empty when the vendor call failed; other fields will be zero values.
// This allows the orchestrator to return partial results instead of aborting the
// entire scan when one vendor is unavailable.
type IPAbuseIPDB struct {
	ConfidenceScore int    `json:"confidenceScore"`
	TotalReports    int    `json:"totalReports"`
	LastReportedAt  string `json:"lastReportedAt,omitempty"`
	Error           string `json:"error,omitempty"`
}

// ── Fetch function ────────────────────────────────────────────────────────────

// FetchAbuseIP queries AbuseIPDB for an IP address.
// ctx is honoured for cancellation.
func FetchAbuseIP(ctx context.Context, ip, apiKey string) (*AbuseIPResult, error) {
	u, _ := url.Parse(abuseEndpoint)
	q := u.Query()
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", "90")
	q.Set("verbose", "true")
	u.RawQuery = q.Encode()

	body, err := httpclient.DoGetCtx(ctx, u.String(), map[string]string{
		"Key":    apiKey,
		"Accept": "application/json",
	})
	if err != nil {
		return nil, fmt.Errorf("AbuseIPDB: %w", err)
	}

	var resp abuseAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("AbuseIPDB parse: %w", err)
	}

	return &AbuseIPResult{
		IPAddress:            resp.Data.IPAddress,
		IsPublic:             resp.Data.IsPublic,
		IsWhitelisted:        resp.Data.IsWhitelisted,
		AbuseConfidenceScore: resp.Data.AbuseConfidenceScore,
		CountryCode:          resp.Data.CountryCode,
		ISP:                  resp.Data.ISP,
		Hostnames:            resp.Data.Hostnames,
		TotalReports:         resp.Data.TotalReports,
		LastReportedAt:       resp.Data.LastReportedAt,
	}, nil
}

// ── Mapping function ──────────────────────────────────────────────────────────

// MapAbuseIPResult converts an AbuseIPResult into the IPAbuseIPDB struct
// used in IP scan output. Called by the IP enrichment orchestrator.
func MapAbuseIPResult(r *AbuseIPResult) IPAbuseIPDB {
	return IPAbuseIPDB{
		ConfidenceScore: r.AbuseConfidenceScore,
		TotalReports:    r.TotalReports,
		LastReportedAt:  r.LastReportedAt,
	}
}
