// utils/iputil.go — IP enrichment: ipapi.is, AbuseIPDB, VirusTotal.
//
// Single source of truth for all API calls and the Lookup entry point
// used by both CLI commands and the web handler.
package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ── Shared HTTP client ────────────────────────────────────────────────────────

var httpClient = &http.Client{Timeout: 15 * time.Second}

// doGet performs a GET request and returns the response body.
func doGet(rawURL string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "iocscan/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, rawURL)
	}
	return io.ReadAll(resp.Body)
}

// ── API endpoint constants ────────────────────────────────────────────────────

const (
	endpointVT      = "https://www.virustotal.com/api/v3/ip_addresses/"
	endpointAbuse   = "https://api.abuseipdb.com/api/v2/check"
	endpointIPApiIs = "https://api.ipapi.is"

	// maxIPs limits how many IPs can be submitted in a single request.
	maxIPs = 100
)

// ── Response structs ──────────────────────────────────────────────────────────

type ipapiResponse struct {
	IP      string `json:"ip"`
	Company struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"company"`
	ASN struct {
		Org string `json:"org"`
	} `json:"asn"`
	Location struct {
		Country  string `json:"country"`
		State    string `json:"state"`
		City     string `json:"city"`
		Timezone string `json:"timezone"`
	} `json:"location"`
}

// SourceLinks holds direct URLs to third-party intel pages for an IP.
type SourceLinks struct {
	IPAPI      string `json:"ipapi"`
	AbuseIPDB  string `json:"abuseipdb"`
	VirusTotal string `json:"virustotal"`
}

func newLinks(ip string) SourceLinks {
	return SourceLinks{
		IPAPI:      "https://api.ipapi.is/?q=" + ip,
		AbuseIPDB:  "https://www.abuseipdb.com/check/" + ip,
		VirusTotal: "https://www.virustotal.com/gui/ip-address/" + ip,
	}
}

// IPSimple is the output of a simple (ipapi.is-only) lookup.
type IPSimple struct {
	IP          string      `json:"ip"`
	CompanyName string      `json:"company_name,omitempty"`
	CompanyType string      `json:"company_type,omitempty"`
	ASNOrg      string      `json:"asn_org,omitempty"`
	Country     string      `json:"country,omitempty"`
	State       string      `json:"state,omitempty"`
	City        string      `json:"city,omitempty"`
	Timezone    string      `json:"timezone,omitempty"`
	RiskLevel   string      `json:"riskLevel"`
	Links       SourceLinks `json:"links"`
}

type abuseResponse struct {
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

type abuseOut struct {
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

type vtResponse struct {
	Data struct {
		ID         string `json:"id"`
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Harmless   int `json:"harmless"`
			} `json:"last_analysis_stats"`
			Reputation int `json:"reputation"`
		} `json:"attributes"`
	} `json:"data"`
}

type vtOut struct {
	// FIX: tag is ipAddress (not "id") so cached JSON is consistent with ComplexResult.
	IPAddress  string `json:"ipAddress"`
	Malicious  int    `json:"malicious"`
	Suspicious int    `json:"suspicious"`
	Undetected int    `json:"undetected"`
	Harmless   int    `json:"harmless"`
	Reputation int    `json:"reputation"`
}

// ComplexResult is the merged output of a complex (ipc) lookup.
// FIX: now includes geo fields (City, State, Timezone) from ipapi.is when available.
type ComplexResult struct {
	IPAddress            string      `json:"ipAddress"`
	Hostnames            []string    `json:"hostnames,omitempty"`
	ISP                  string      `json:"isp,omitempty"`
	Country              string      `json:"country,omitempty"` // from ipapi.is (richer than countryCode)
	CountryCode          string      `json:"countryCode,omitempty"`
	City                 string      `json:"city,omitempty"`
	State                string      `json:"state,omitempty"`
	Timezone             string      `json:"timezone,omitempty"`
	IsPublic             bool        `json:"isPublic"`
	IsWhitelisted        bool        `json:"isWhitelisted"`
	TotalReports         int         `json:"totalReports"`
	AbuseConfidenceScore int         `json:"abuseConfidenceScore"`
	LastReportedAt       string      `json:"lastReportedAt,omitempty"`
	VTMalicious          int         `json:"vtMalicious"`
	VTSuspicious         int         `json:"vtSuspicious"`
	VTStatsSUH           string      `json:"vtStats_S_U_H"` // suspicious/undetected/harmless
	VTReputation         int         `json:"vtReputation"`
	RiskLevel            string      `json:"riskLevel"`
	Links                SourceLinks `json:"links"`
}

// ── IPProcessor ──────────────────────────────────────────────────────────────

// IPProcessor holds API keys and exposes the Lookup method.
type IPProcessor struct {
	vtKey    string
	abuseKey string
	ipapiKey string
}

// NewIPProcessor constructs an IPProcessor.
func NewIPProcessor(vtKey, abuseKey, ipapiKey string) *IPProcessor {
	return &IPProcessor{vtKey: vtKey, abuseKey: abuseKey, ipapiKey: ipapiKey}
}

// CheckIP parses a comma/newline/space/tab-separated string of IPs,
// validates each one, and enforces the maxIPs limit.
func CheckIP(raw string) ([]string, error) {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\r' || r == '\n' || r == ',' || r == ' ' || r == '\t'
	})

	ips := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if net.ParseIP(p) == nil {
			return nil, fmt.Errorf("%q is not a valid IP address", p)
		}
		ips = append(ips, p)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no valid IP addresses provided")
	}
	if len(ips) > maxIPs {
		return nil, fmt.Errorf("too many IPs: %d provided, maximum is %d", len(ips), maxIPs)
	}
	return ips, nil
}

// Lookup queries the appropriate APIs based on mode:
//   - "simple"  → ipapi.is only
//   - "complex" → AbuseIPDB + VirusTotal + optional ipapi.is (concurrent)
//
// useCache controls whether the SQLite cache is consulted.
// Returns clean JSON (no trailing comma).
func (p *IPProcessor) Lookup(ip, mode string, useCache bool) (string, error) {
	if strings.ToLower(mode) == "simple" {
		return p.lookupSimple(ip, useCache)
	}
	return p.lookupComplex(ip, useCache)
}

// ── Simple lookup (ipapi.is) ──────────────────────────────────────────────────

func (p *IPProcessor) lookupSimple(ip string, useCache bool) (string, error) {
	if useCache {
		if cached := getCached(ip, "IPAPIIS_IP"); cached != "" {
			return cached, nil
		}
	}

	raw, err := p.fetchIPApi(ip)
	if err != nil {
		return "", err
	}

	out := IPSimple{
		IP:          raw.IP,
		CompanyName: raw.Company.Name,
		CompanyType: raw.Company.Type,
		ASNOrg:      raw.ASN.Org,
		Country:     raw.Location.Country,
		State:       raw.Location.State,
		City:        raw.Location.City,
		Timezone:    raw.Location.Timezone,
		RiskLevel:   "CLEAN", // no abuse/VT data in simple mode
		Links:       newLinks(ip),
	}

	j, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", err
	}
	putCached(ip, string(j), "IPAPIIS_IP")
	return string(j), nil
}

// ── Complex lookup (AbuseIPDB + VirusTotal + ipapi.is, concurrent) ───────────

// lookupResult is used to pass results out of goroutines via channels.
type abuseResult struct {
	data *abuseOut
	err  error
}
type vtResult struct {
	data *vtOut
	err  error
}
type geoResult struct {
	data *ipapiResponse
	err  error
}

func (p *IPProcessor) lookupComplex(ip string, useCache bool) (string, error) {
	abuseCh := make(chan abuseResult, 1)
	vtCh := make(chan vtResult, 1)
	geoCh := make(chan geoResult, 1)

	go func() {
		d, e := p.fetchAbuse(ip, useCache)
		abuseCh <- abuseResult{d, e}
	}()
	go func() {
		d, e := p.fetchVT(ip, useCache)
		vtCh <- vtResult{d, e}
	}()
	go func() {
		// ipapi.is enrichment is optional — only called when a key is configured
		// or when the free tier is acceptable (key can be empty).
		d, e := p.fetchIPApi(ip)
		geoCh <- geoResult{d, e}
	}()

	ar := <-abuseCh
	vr := <-vtCh
	gr := <-geoCh

	if ar.err != nil {
		return "", fmt.Errorf("AbuseIPDB: %w", ar.err)
	}
	if vr.err != nil {
		return "", fmt.Errorf("VirusTotal: %w", vr.err)
	}
	// geo errors are non-fatal — we just skip those fields.

	result := ComplexResult{
		IPAddress:            ar.data.IPAddress,
		Hostnames:            ar.data.Hostnames,
		ISP:                  ar.data.ISP,
		CountryCode:          ar.data.CountryCode,
		IsPublic:             ar.data.IsPublic,
		IsWhitelisted:        ar.data.IsWhitelisted,
		TotalReports:         ar.data.TotalReports,
		AbuseConfidenceScore: ar.data.AbuseConfidenceScore,
		LastReportedAt:       ar.data.LastReportedAt,
		VTMalicious:          vr.data.Malicious,
		VTSuspicious:         vr.data.Suspicious,
		VTStatsSUH:           fmt.Sprintf("%d/%d/%d", vr.data.Suspicious, vr.data.Undetected, vr.data.Harmless),
		VTReputation:         vr.data.Reputation,
		RiskLevel:            assessRisk(ar.data.AbuseConfidenceScore, vr.data.Malicious),
		Links:                newLinks(ip),
	}

	// Merge geo data if available.
	if gr.err == nil && gr.data != nil {
		result.Country = gr.data.Location.Country
		result.City = gr.data.Location.City
		result.State = gr.data.Location.State
		result.Timezone = gr.data.Location.Timezone
		// Prefer ISP from AbuseIPDB but fall back to ipapi.is ASN org.
		if result.ISP == "" {
			result.ISP = gr.data.ASN.Org
		}
	}

	j, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(j), nil
}

// assessRisk derives a risk level from AbuseIPDB score and VT malicious count.
func assessRisk(abuseScore, vtMalicious int) string {
	switch {
	case abuseScore >= 75 || vtMalicious >= 5:
		return "CRITICAL"
	case abuseScore >= 40 || vtMalicious >= 2:
		return "HIGH"
	case abuseScore >= 10 || vtMalicious >= 1:
		return "MEDIUM"
	case abuseScore > 0:
		return "LOW"
	default:
		return "CLEAN"
	}
}

// ── ipapi.is ─────────────────────────────────────────────────────────────────

func (p *IPProcessor) fetchIPApi(ip string) (*ipapiResponse, error) {
	reqURL := fmt.Sprintf("%s/?q=%s", endpointIPApiIs, url.QueryEscape(ip))
	if p.ipapiKey != "" {
		reqURL += "&key=" + url.QueryEscape(p.ipapiKey)
	}

	body, err := doGet(reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("ipapi.is: %w", err)
	}

	var raw ipapiResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("ipapi.is parse: %w", err)
	}
	return &raw, nil
}

// ── AbuseIPDB ─────────────────────────────────────────────────────────────────

func (p *IPProcessor) fetchAbuse(ip string, useCache bool) (*abuseOut, error) {
	if useCache {
		if cached := getCached(ip, "ABUSE_IP"); cached != "" {
			var out abuseOut
			if err := json.Unmarshal([]byte(cached), &out); err == nil {
				return &out, nil
			}
		}
	}

	u, _ := url.Parse(endpointAbuse)
	q := u.Query()
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", "90")
	q.Set("verbose", "true")
	u.RawQuery = q.Encode()

	body, err := doGet(u.String(), map[string]string{
		"Key":    p.abuseKey,
		"Accept": "application/json",
	})
	if err != nil {
		return nil, err
	}

	var resp abuseResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	out := abuseOut{
		IPAddress:            resp.Data.IPAddress,
		IsPublic:             resp.Data.IsPublic,
		IsWhitelisted:        resp.Data.IsWhitelisted,
		AbuseConfidenceScore: resp.Data.AbuseConfidenceScore,
		CountryCode:          resp.Data.CountryCode,
		ISP:                  resp.Data.ISP,
		Hostnames:            resp.Data.Hostnames,
		TotalReports:         resp.Data.TotalReports,
		LastReportedAt:       resp.Data.LastReportedAt,
	}

	if j, err := json.Marshal(out); err == nil {
		putCached(ip, string(j), "ABUSE_IP")
	}
	return &out, nil
}

// ── VirusTotal ────────────────────────────────────────────────────────────────

func (p *IPProcessor) fetchVT(ip string, useCache bool) (*vtOut, error) {
	if useCache {
		if cached := getCached(ip, "VT_IP"); cached != "" {
			var out vtOut
			if err := json.Unmarshal([]byte(cached), &out); err == nil {
				return &out, nil
			}
		}
	}

	body, err := doGet(endpointVT+ip, map[string]string{"x-apikey": p.vtKey})
	if err != nil {
		return nil, err
	}

	var resp vtResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	out := vtOut{
		IPAddress:  resp.Data.ID,
		Malicious:  resp.Data.Attributes.LastAnalysisStats.Malicious,
		Suspicious: resp.Data.Attributes.LastAnalysisStats.Suspicious,
		Undetected: resp.Data.Attributes.LastAnalysisStats.Undetected,
		Harmless:   resp.Data.Attributes.LastAnalysisStats.Harmless,
		Reputation: resp.Data.Attributes.Reputation,
	}

	if j, err := json.Marshal(out); err == nil {
		putCached(ip, string(j), "VT_IP")
	}
	return &out, nil
}
