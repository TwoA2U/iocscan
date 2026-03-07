// integrations/threatfox.go — ThreatFox enrichment for IP addresses and file hashes.
//
// API docs: https://threatfox.abuse.ch/api/
//
// IP lookup:   POST {"query": "search_ioc",  "search_term": "<ip>"}
// Hash lookup: POST {"query": "search_hash", "hash": "<sha256>"}
//
// Auth: Auth-Key header (optional — public tier works without a key).
package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/TwoA2U/iocscan/internal/httpclient"
)

const tfEndpoint = "https://threatfox-api.abuse.ch/api/v1/"

// ── Raw API response structs ──────────────────────────────────────────────────

// tfResponse is the top-level envelope returned by every ThreatFox query.
type tfResponse struct {
	QueryStatus string    `json:"query_status"`
	Data        []tfEntry `json:"data"`
}

// tfEntry is one IOC record from ThreatFox.
// Both IP and hash responses share the same structure;
// malware_samples is only present in IP responses.
type tfEntry struct {
	IOC             string            `json:"ioc"`
	ThreatType      string            `json:"threat_type"`
	ThreatTypeDesc  string            `json:"threat_type_desc"`
	IOCType         string            `json:"ioc_type"`
	Malware         string            `json:"malware"`
	MalwarePrint    string            `json:"malware_printable"`
	MalwareAlias    string            `json:"malware_alias"`
	MalwareMalpedia string            `json:"malware_malpedia"`
	ConfidenceLevel int               `json:"confidence_level"`
	FirstSeen       string            `json:"first_seen"`
	LastSeen        *string           `json:"last_seen"`
	Reporter        string            `json:"reporter"`
	Tags            []string          `json:"tags"`
	Samples         []tfMalwareSample `json:"malware_samples"`
}

// tfMalwareSample is an associated malware sample returned in IP lookups.
type tfMalwareSample struct {
	TimeStamp     string `json:"time_stamp"`
	MD5Hash       string `json:"md5_hash"`
	SHA256Hash    string `json:"sha256_hash"`
	MalwareBazaar string `json:"malware_bazaar"`
}

// ── Output structs ────────────────────────────────────────────────────────────

// TFMalwareSample is the cleaned malware sample included in IP results.
type TFMalwareSample struct {
	SHA256Hash    string `json:"sha256_hash"`
	MalwareBazaar string `json:"malware_bazaar"`
}

// TFIPResult is the enriched ThreatFox result for an IP indicator.
// Only the first matching IOC entry is used; samples come from that entry.
type TFIPResult struct {
	QueryStatus     string            `json:"queryStatus"`
	ThreatType      string            `json:"threatType,omitempty"`
	Malware         string            `json:"malware,omitempty"`
	MalwareAlias    string            `json:"malwareAlias,omitempty"`
	ConfidenceLevel int               `json:"confidenceLevel,omitempty"`
	FirstSeen       string            `json:"firstSeen,omitempty"`
	LastSeen        string            `json:"lastSeen,omitempty"`
	Reporter        string            `json:"reporter,omitempty"`
	Tags            []string          `json:"tags,omitempty"`
	MalwareSamples  []TFMalwareSample `json:"malwareSamples,omitempty"`
}

// TFHashEntry is one IOC record from a ThreatFox hash lookup.
// Hash queries can return multiple associated URLs/IOCs for the same hash.
type TFHashEntry struct {
	IOC             string   `json:"ioc"`
	ThreatType      string   `json:"threatType"`
	Malware         string   `json:"malware"`
	MalwareAlias    string   `json:"malwareAlias,omitempty"`
	ConfidenceLevel int      `json:"confidenceLevel"`
	FirstSeen       string   `json:"firstSeen"`
	Reporter        string   `json:"reporter,omitempty"`
	Tags            []string `json:"tags,omitempty"`
}

// TFHashResult is the enriched ThreatFox result for a hash indicator.
type TFHashResult struct {
	QueryStatus string        `json:"queryStatus"`
	IOCs        []TFHashEntry `json:"iocs,omitempty"`
}

// ── HTTP helper ───────────────────────────────────────────────────────────────

// doTFPost sends a JSON POST to ThreatFox and returns the raw response body.
// ctx is honoured for cancellation.
// apiKey may be empty — ThreatFox has a public tier that works without auth.
func doTFPost(ctx context.Context, payload interface{}, apiKey string) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("threatfox marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tfEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("threatfox request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "iocscan/1.0")
	if apiKey != "" {
		req.Header.Set("Auth-Key", apiKey)
	}

	resp, err := httpclient.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("threatfox http: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("threatfox read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("threatfox HTTP %d: %.200s", resp.StatusCode, string(raw))
	}
	return raw, nil
}

// ── IP lookup ─────────────────────────────────────────────────────────────────

// FetchTFIP queries ThreatFox for an IP indicator.
// ctx is honoured for cancellation.
func FetchTFIP(ctx context.Context, ip, apiKey string) (*TFIPResult, error) {
	raw, err := doTFPost(ctx, map[string]string{
		"query":       "search_ioc",
		"search_term": ip,
	}, apiKey)
	if err != nil {
		return &TFIPResult{QueryStatus: "error"}, fmt.Errorf("FetchTFIP: %w", err)
	}

	var resp tfResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return &TFIPResult{QueryStatus: "parse_error"}, fmt.Errorf("FetchTFIP parse: %w", err)
	}
	return parseTFIPResult(resp), nil
}

// parseTFIPResult maps the raw ThreatFox response into TFIPResult.
func parseTFIPResult(resp tfResponse) *TFIPResult {
	result := &TFIPResult{QueryStatus: resp.QueryStatus}
	if resp.QueryStatus != "ok" || len(resp.Data) == 0 {
		return result
	}

	e := resp.Data[0] // use the first (highest-confidence) entry
	result.ThreatType = e.ThreatType
	result.Malware = e.Malware
	result.MalwareAlias = e.MalwareAlias
	result.ConfidenceLevel = e.ConfidenceLevel
	result.FirstSeen = e.FirstSeen
	if e.LastSeen != nil {
		result.LastSeen = *e.LastSeen
	}
	result.Reporter = e.Reporter
	if len(e.Tags) > 0 {
		result.Tags = e.Tags
	}
	for _, s := range e.Samples {
		if s.SHA256Hash == "" {
			continue
		}
		result.MalwareSamples = append(result.MalwareSamples, TFMalwareSample{
			SHA256Hash:    s.SHA256Hash,
			MalwareBazaar: s.MalwareBazaar,
		})
	}
	return result
}

// ── Hash lookup ───────────────────────────────────────────────────────────────

// FetchTFHash queries ThreatFox for a file hash.
// ctx is honoured for cancellation.
func FetchTFHash(ctx context.Context, hash, apiKey string) (*TFHashResult, error) {
	raw, err := doTFPost(ctx, map[string]string{
		"query": "search_hash",
		"hash":  hash,
	}, apiKey)
	if err != nil {
		return &TFHashResult{QueryStatus: "error"}, fmt.Errorf("FetchTFHash: %w", err)
	}

	var resp tfResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return &TFHashResult{QueryStatus: "parse_error"}, fmt.Errorf("FetchTFHash parse: %w", err)
	}
	return parseTFHashResult(resp), nil
}

// parseTFHashResult maps the raw ThreatFox response into TFHashResult.
func parseTFHashResult(resp tfResponse) *TFHashResult {
	result := &TFHashResult{QueryStatus: resp.QueryStatus}
	if resp.QueryStatus != "ok" || len(resp.Data) == 0 {
		return result
	}
	for _, e := range resp.Data {
		entry := TFHashEntry{
			IOC:             e.IOC,
			ThreatType:      e.ThreatType,
			Malware:         e.Malware,
			MalwareAlias:    e.MalwareAlias,
			ConfidenceLevel: e.ConfidenceLevel,
			FirstSeen:       e.FirstSeen,
			Reporter:        e.Reporter,
			Tags:            e.Tags,
		}
		if entry.Tags == nil {
			entry.Tags = []string{}
		}
		result.IOCs = append(result.IOCs, entry)
	}
	return result
}
