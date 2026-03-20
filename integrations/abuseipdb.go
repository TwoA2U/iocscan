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
		NumDistinctUsers     int      `json:"numDistinctUsers"`
		LastReportedAt       string   `json:"lastReportedAt"`
		UsageType            string   `json:"usageType"`
		Domain               string   `json:"domain"`
		IsTor                bool     `json:"isTor"`
		Reports              []struct {
			Categories []int `json:"categories"`
		} `json:"reports"`
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
	NumDistinctUsers     int      `json:"numDistinctUsers"`
	LastReportedAt       string   `json:"lastReportedAt"`
	UsageType            string   `json:"usageType,omitempty"`
	Domain               string   `json:"domain,omitempty"`
	IsTor                bool     `json:"isTor"`
	Categories           []string `json:"categories,omitempty"`
}

// IPAbuseIPDB holds the AbuseIPDB enrichment fields surfaced in an IP scan result.
// Error is non-empty when the vendor call failed; other fields will be zero values.
// This allows the orchestrator to return partial results instead of aborting the
// entire scan when one vendor is unavailable.
type IPAbuseIPDB struct {
	ConfidenceScore  int      `json:"confidenceScore"`
	TotalReports     int      `json:"totalReports"`
	NumDistinctUsers int      `json:"numDistinctUsers"`
	LastReportedAt   string   `json:"lastReportedAt,omitempty"`
	UsageType        string   `json:"usageType,omitempty"`
	Domain           string   `json:"domain,omitempty"`
	IsTor            bool     `json:"isTor"`
	IsPublic         bool     `json:"isPublic"`
	IsWhitelisted    bool     `json:"isWhitelisted"`
	Hostnames        []string `json:"hostnames,omitempty"`
	Categories       []string `json:"categories,omitempty"`
	Error            string   `json:"error,omitempty"`
}

// abuseCategories maps AbuseIPDB category IDs to human-readable names.
// Source: https://www.abuseipdb.com/categories
var abuseCategories = map[int]string{
	1:  "DNS Compromise",
	2:  "DNS Poisoning",
	3:  "Fraud Orders",
	4:  "DDoS Attack",
	5:  "FTP Brute-Force",
	6:  "Ping of Death",
	7:  "Phishing",
	8:  "Fraud VoIP",
	9:  "Open Proxy",
	10: "Web Spam",
	11: "Email Spam",
	12: "Blog Spam",
	13: "VPN IP",
	14: "Port Scan",
	15: "Hacking",
	16: "SQL Injection",
	17: "Spoofing",
	18: "Brute-Force",
	19: "Bad Web Bot",
	20: "Exploited Host",
	21: "Web App Attack",
	22: "SSH",
	23: "IoT Targeted",
}

// resolveCategories deduplicates category IDs across all reports and
// returns a sorted slice of human-readable category names.
func resolveCategories(reports []struct {
	Categories []int `json:"categories"`
}) []string {
	seen := make(map[int]bool)
	for _, r := range reports {
		for _, id := range r.Categories {
			seen[id] = true
		}
	}
	names := make([]string, 0, len(seen))
	// Iterate in ID order for stable output
	for id := 1; id <= 23; id++ {
		if seen[id] {
			if name, ok := abuseCategories[id]; ok {
				names = append(names, name)
			}
		}
	}
	return names
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
		NumDistinctUsers:     resp.Data.NumDistinctUsers,
		LastReportedAt:       resp.Data.LastReportedAt,
		UsageType:            resp.Data.UsageType,
		Domain:               resp.Data.Domain,
		IsTor:                resp.Data.IsTor,
		Categories:           resolveCategories(resp.Data.Reports),
	}, nil
}

// ── Mapping function ──────────────────────────────────────────────────────────

// MapAbuseIPResult converts an AbuseIPResult into the IPAbuseIPDB struct
// used in IP scan output. Called by the IP enrichment orchestrator.
func MapAbuseIPResult(r *AbuseIPResult) IPAbuseIPDB {
	return IPAbuseIPDB{
		ConfidenceScore:  r.AbuseConfidenceScore,
		TotalReports:     r.TotalReports,
		NumDistinctUsers: r.NumDistinctUsers,
		LastReportedAt:   r.LastReportedAt,
		UsageType:        r.UsageType,
		Domain:           r.Domain,
		IsTor:            r.IsTor,
		IsPublic:         r.IsPublic,
		IsWhitelisted:    r.IsWhitelisted,
		Hostnames:        r.Hostnames,
		Categories:       r.Categories,
	}
}

// ── Integration interface implementation ──────────────────────────────────────
//
// AbuseIPDBIntegration wraps FetchAbuseIP to satisfy the Integration interface.
// Named with the "Integration" suffix to avoid colliding with the existing
// IPAbuseIPDB output type defined above.

type AbuseIPDBIntegration struct{}

func (a AbuseIPDBIntegration) Manifest() Manifest {
	return Manifest{
		Name:     "abuseipdb",
		Label:    "AbuseIPDB",
		Icon:     "🚨",
		Enabled:  true,
		IOCTypes: []IOCType{IOCTypeIP},
		Auth: AuthConfig{
			KeyRef:   "abuse",
			Label:    "AbuseIPDB",
			Optional: false,
		},
		Cache: CacheConfig{
			Table:    "ABUSE_IP",
			TTLHours: 12,
		},
		RiskRules: []RiskRule{
			{
				Field: "confidenceScore",
				Type:  RiskThreshold,
				Thresholds: []RiskThresholdRule{
					{Gte: 75, Level: "CRITICAL"},
					{Gte: 40, Level: "HIGH"},
					{Gte: 10, Level: "MEDIUM"},
					{Gte: 1, Level: "LOW"},
				},
			},
		},
		Card: CardDef{
			Title:        "🚨 AbuseIPDB",
			Order:        2,
			LinkTemplate: "https://www.abuseipdb.com/check/{ioc}",
			LinkLabel:    "↗ AbuseIPDB",
			Fields: []FieldDef{
				{
					Key:   "confidenceScore",
					Label: "Confidence Score",
					Type:  FieldTypeScoreBar,
					Thresholds: []ScoreThreshold{
						{Gte: 75, Color: "#f87171"},
						{Gte: 40, Color: "#fb923c"},
						{Gte: 1, Color: "#fbbf24"},
						{Gte: 0, Color: "#34d399"},
					},
				},
				{Key: "totalReports", Label: "Total Reports", Type: FieldTypeNumber},
				{Key: "lastReportedAt", Label: "Last Reported", Type: FieldTypeString},
				{Key: "isp", Label: "ISP", Type: FieldTypeString},
				{Key: "countryCode", Label: "Country", Type: FieldTypeString},
				{
					Key:        "isPublic",
					Label:      "Public IP",
					Type:       FieldTypeBool,
					TrueLabel:  "Yes",
					FalseLabel: "No",
					TrueColor:  "#94a3b8",
					FalseColor: "#34d399",
				},
				{
					Key:        "isWhitelisted",
					Label:      "Whitelisted",
					Type:       FieldTypeBool,
					TrueLabel:  "Yes",
					FalseLabel: "No",
					TrueColor:  "#34d399",
					FalseColor: "#94a3b8",
				},
				{Key: "hostnames", Label: "Hostnames", Type: FieldTypeTags},
			},
		},
		TableColumns: []TableColumn{
			{Key: "confidenceScore", Label: "Abuse %", DefaultVisible: true},
			{Key: "totalReports", Label: "Reports", DefaultVisible: true},
			{Key: "lastReportedAt", Label: "Last Reported", DefaultVisible: true},
			{Key: "isp", Label: "ISP", DefaultVisible: false},
			{Key: "countryCode", Label: "Country", DefaultVisible: false},
		},
	}
}

func (a AbuseIPDBIntegration) Run(ctx context.Context, ioc, apiKey string, useCache bool) (*Result, error) {
	if useCache {
		if raw := cachedGet(ioc, "ABUSE_IP"); raw != "" {
			var r AbuseIPResult
			if err := json.Unmarshal([]byte(raw), &r); err == nil {
				res := abuseToResult(&r)
				res.FromCache = true
				return res, nil
			}
		}
	}

	r, err := FetchAbuseIP(ctx, ioc, apiKey)
	if err != nil {
		return &Result{Error: err.Error()}, nil
	}

	if b, e := json.Marshal(r); e == nil {
		cachedPut(ioc, string(b), "ABUSE_IP")
	}
	return abuseToResult(r), nil
}

func abuseToResult(r *AbuseIPResult) *Result {
	return &Result{Fields: map[string]any{
		"ipAddress":        r.IPAddress,
		"confidenceScore":  r.AbuseConfidenceScore,
		"totalReports":     r.TotalReports,
		"numDistinctUsers": r.NumDistinctUsers,
		"lastReportedAt":   r.LastReportedAt,
		"usageType":        r.UsageType,
		"domain":           r.Domain,
		"isTor":            r.IsTor,
		"categories":       r.Categories,
		"isp":              r.ISP,
		"countryCode":      r.CountryCode,
		"isPublic":         r.IsPublic,
		"isWhitelisted":    r.IsWhitelisted,
		"hostnames":        r.Hostnames,
	}}
}
