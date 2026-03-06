// integrations/abuseipdb.go — AbuseIPDB enrichment for IP addresses.
//
// API docs: https://docs.abuseipdb.com/#check-endpoint
//
// Endpoint: GET https://api.abuseipdb.com/api/v2/check
// Auth: Key header (required).
package integrations

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/TwoA2U/iocscan/internal/httpclient"
)

const abuseEndpoint = "https://api.abuseipdb.com/api/v2/check"

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

// AbuseIPResult holds the cleaned AbuseIPDB enrichment for an IP address.
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

// FetchAbuseIP queries AbuseIPDB for an IP address.
func FetchAbuseIP(ip, apiKey string) (*AbuseIPResult, error) {
	u, _ := url.Parse(abuseEndpoint)
	q := u.Query()
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", "90")
	q.Set("verbose", "true")
	u.RawQuery = q.Encode()

	body, err := httpclient.DoGet(u.String(), map[string]string{
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
