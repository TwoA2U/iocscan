// utils/iputil.go — IP enrichment orchestrator.
//
// Coordinates concurrent enrichment of an IP address across all configured
// threat-intelligence vendors and assembles the unified ComplexResult.
//
// All scans run in "complex" mode: AbuseIPDB + VirusTotal + ipapi.is + ThreatFox
// are queried concurrently. If a vendor call fails the result is still returned
// with the error surfaced in the relevant vendor field (partial-result behaviour).
//
// Context propagation — Lookup / lookupComplex accept a context.Context threaded
// from the HTTP handler, so a browser disconnect cancels in-flight vendor
// goroutines instead of burning API quota.
//
// Vendor-specific types and mapping logic live in the integrations/ package:
//   integrations/virustotal.go  → IPVirusTotal, MapVTIPResult
//   integrations/abuseipdb.go  → IPAbuseIPDB, MapAbuseIPResult
//   integrations/threatfox.go  → TFIPResult (used directly, no extra mapping needed)
//   integrations/ipapi.go      → IPAPIResponse (fields merged into IPGeo here)
//
// Public API:
//   NewIPProcessor(vtKey, abuseKey, ipapiKey, abusechKey) *IPProcessor
//   (*IPProcessor).Lookup(ctx, ip string, useCache bool) (string, error)
//   CheckIP(raw string) ([]string, error)
package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/TwoA2U/iocscan/integrations"
)

const maxIPs = 100

// ── Output types ──────────────────────────────────────────────────────────────

// IPLinks holds direct URLs to third-party pages for an IP address.
type IPLinks struct {
	IPAPI      string `json:"ipapi"`
	AbuseIPDB  string `json:"abuseipdb"`
	VirusTotal string `json:"virustotal"`
}

func newIPLinks(ip string) IPLinks {
	return IPLinks{
		IPAPI:      "https://api.ipapi.is/?q=" + ip,
		AbuseIPDB:  "https://www.abuseipdb.com/check/" + ip,
		VirusTotal: "https://www.virustotal.com/gui/ip-address/" + ip,
	}
}

// IPGeo holds geographic and network identity data merged from ipapi.is + AbuseIPDB.
// It is a cross-vendor composite type, so it lives in the orchestrator.
type IPGeo struct {
	ISP           string   `json:"isp,omitempty"`
	Country       string   `json:"country,omitempty"`
	CountryCode   string   `json:"countryCode,omitempty"`
	City          string   `json:"city,omitempty"`
	State         string   `json:"state,omitempty"`
	Timezone      string   `json:"timezone,omitempty"`
	IsPublic      bool     `json:"isPublic"`
	IsWhitelisted bool     `json:"isWhitelisted"`
	Hostnames     []string `json:"hostnames,omitempty"`
}

// ComplexResult is the vendor-grouped, unified output of an IP lookup.
// Vendor-specific sub-structs (IPVirusTotal, IPAbuseIPDB) are defined in their
// respective integrations/ files.
type ComplexResult struct {
	IPAddress string  `json:"ipAddress"`
	RiskLevel string  `json:"riskLevel"`
	Links     IPLinks `json:"links"`

	Geo        IPGeo                     `json:"geo"`
	VirusTotal integrations.IPVirusTotal `json:"virustotal"`
	AbuseIPDB  integrations.IPAbuseIPDB  `json:"abuseipdb"`
	ThreatFox  *integrations.TFIPResult  `json:"threatfox,omitempty"`
}

// ── IPProcessor ───────────────────────────────────────────────────────────────

type IPProcessor struct {
	vtKey      string
	abuseKey   string
	ipapiKey   string
	abusechKey string
}

func NewIPProcessor(vtKey, abuseKey, ipapiKey, abusechKey string) *IPProcessor {
	return &IPProcessor{vtKey: vtKey, abuseKey: abuseKey, ipapiKey: ipapiKey, abusechKey: abusechKey}
}

// CheckIP parses and validates one or more IP addresses from a raw string.
// IPs may be separated by newlines, commas, spaces, or tabs.
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

// Lookup enriches a single IP address using all configured vendors concurrently.
// ctx is threaded through to all vendor HTTP calls so a cancelled request
// (e.g. browser disconnect) aborts in-flight work immediately.
func (p *IPProcessor) Lookup(ctx context.Context, ip string, useCache bool) (string, error) {
	return p.lookupComplex(ctx, ip, useCache)
}

// ── Per-vendor channel types (internal to lookupComplex) ─────────────────────

type abuseResult struct {
	data *integrations.AbuseIPResult
	err  error
}
type vtIPResult struct {
	data *integrations.VTIPResult
	err  error
}
type geoResult struct {
	data *integrations.IPAPIResponse
	err  error
}
type tfIPRes struct {
	data *integrations.TFIPResult
	err  error
}

func (p *IPProcessor) lookupComplex(ctx context.Context, ip string, useCache bool) (string, error) {
	abuseCh := make(chan abuseResult, 1)
	vtCh := make(chan vtIPResult, 1)
	geoCh := make(chan geoResult, 1)
	tfCh := make(chan tfIPRes, 1)

	// ── AbuseIPDB ─────────────────────────────────────────────────────────────
	go func() {
		if useCache {
			if cached := getCacheEntry(ip, "ABUSE_IP"); cached != "" {
				var out integrations.AbuseIPResult
				if err := json.Unmarshal([]byte(cached), &out); err == nil {
					abuseCh <- abuseResult{data: &out}
					return
				}
			}
		}
		d, err := integrations.FetchAbuseIP(ctx, ip, p.abuseKey)
		if err == nil && d != nil {
			if j, e := json.Marshal(d); e == nil {
				putCacheEntry(ip, string(j), "ABUSE_IP")
			}
		}
		abuseCh <- abuseResult{data: d, err: err}
	}()

	// ── VirusTotal ────────────────────────────────────────────────────────────
	go func() {
		if useCache {
			if cached := getCacheEntry(ip, "VT_IP"); cached != "" {
				var out integrations.VTIPResult
				if err := json.Unmarshal([]byte(cached), &out); err == nil {
					vtCh <- vtIPResult{data: &out}
					return
				}
			}
		}
		d, err := integrations.FetchVTIP(ctx, ip, p.vtKey)
		if err == nil && d != nil {
			if j, e := json.Marshal(d); e == nil {
				putCacheEntry(ip, string(j), "VT_IP")
			}
		}
		vtCh <- vtIPResult{data: d, err: err}
	}()

	// ── ipapi.is ──────────────────────────────────────────────────────────────
	go func() {
		if useCache {
			if cached := getCacheEntry(ip, "IPAPIIS_IP"); cached != "" {
				var out integrations.IPAPIResponse
				if err := json.Unmarshal([]byte(cached), &out); err == nil {
					geoCh <- geoResult{data: &out}
					return
				}
			}
		}
		d, err := integrations.FetchIPAPI(ctx, ip, p.ipapiKey)
		if err == nil && d != nil {
			if j, e := json.Marshal(d); e == nil {
				putCacheEntry(ip, string(j), "IPAPIIS_IP")
			}
		}
		geoCh <- geoResult{data: d, err: err}
	}()

	// ── ThreatFox ─────────────────────────────────────────────────────────────
	go func() {
		if useCache {
			if cached := getCacheEntry(ip, "TF_IP"); cached != "" {
				var out integrations.TFIPResult
				if err := json.Unmarshal([]byte(cached), &out); err == nil {
					tfCh <- tfIPRes{data: &out}
					return
				}
			}
		}
		d, err := integrations.FetchTFIP(ctx, ip, p.abusechKey)
		if d != nil {
			if j, e := json.Marshal(d); e == nil {
				putCacheEntry(ip, string(j), "TF_IP")
			}
		}
		tfCh <- tfIPRes{data: d, err: err}
	}()

	ar := <-abuseCh
	vr := <-vtCh
	gr := <-geoCh
	tr := <-tfCh

	// Check for context cancellation — if the caller already gave up, don't
	// bother assembling and marshalling a result nobody will read.
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("request cancelled: %w", err)
	}

	result := ComplexResult{
		IPAddress: ip,
		Links:     newIPLinks(ip),
	}

	// ── Populate AbuseIPDB — partial result on error ──────────────────────────
	// Previously the whole scan failed if AbuseIPDB errored. Now we return
	// whatever we have and surface the error in the vendor field so the UI can
	// show partial data instead of nothing.
	if ar.err != nil {
		result.AbuseIPDB = integrations.IPAbuseIPDB{
			Error: ar.err.Error(),
		}
	} else if ar.data != nil {
		result.IPAddress = ar.data.IPAddress
		result.AbuseIPDB = integrations.MapAbuseIPResult(ar.data)
		result.Geo = IPGeo{
			ISP:           ar.data.ISP,
			CountryCode:   ar.data.CountryCode,
			IsPublic:      ar.data.IsPublic,
			IsWhitelisted: ar.data.IsWhitelisted,
			Hostnames:     ar.data.Hostnames,
		}
	}

	// ── Populate VirusTotal — partial result on error ─────────────────────────
	abuseScore := 0
	vtMalicious := 0
	if vr.err != nil {
		result.VirusTotal = integrations.IPVirusTotal{
			Error: vr.err.Error(),
		}
	} else if vr.data != nil {
		result.VirusTotal = integrations.MapVTIPResult(vr.data)
		vtMalicious = vr.data.Malicious
	}
	if ar.data != nil {
		abuseScore = ar.data.AbuseConfidenceScore
	}

	// ── Merge ipapi.is geo fields ─────────────────────────────────────────────
	if gr.err == nil && gr.data != nil {
		result.Geo.Country = gr.data.Location.Country
		result.Geo.City = gr.data.Location.City
		result.Geo.State = gr.data.Location.State
		result.Geo.Timezone = gr.data.Location.Timezone
		if result.Geo.ISP == "" {
			result.Geo.ISP = gr.data.ASN.Org
		}
	}

	// ── ThreatFox ─────────────────────────────────────────────────────────────
	if tr.data != nil {
		result.ThreatFox = tr.data
	} else if tr.err != nil {
		result.ThreatFox = &integrations.TFIPResult{QueryStatus: "error"}
	}

	tfConfidence := 0
	if tr.data != nil && tr.data.QueryStatus == "ok" {
		tfConfidence = tr.data.ConfidenceLevel
	}
	result.RiskLevel = assessRisk(abuseScore, vtMalicious, tfConfidence)

	j, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(j), nil
}

// ── Risk assessment ───────────────────────────────────────────────────────────

// assessRisk computes a risk level from three independent signals.
// Any single high-confidence signal is sufficient to escalate the level.
func assessRisk(abuseScore, vtMalicious, tfConfidence int) string {
	switch {
	case abuseScore >= 75 || vtMalicious >= 5 || tfConfidence >= 75:
		return "CRITICAL"
	case abuseScore >= 40 || vtMalicious >= 2 || tfConfidence >= 50:
		return "HIGH"
	case abuseScore >= 10 || vtMalicious >= 1 || tfConfidence > 0:
		return "MEDIUM"
	case abuseScore > 0:
		return "LOW"
	default:
		return "CLEAN"
	}
}
