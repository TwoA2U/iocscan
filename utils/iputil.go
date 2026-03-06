// utils/iputil.go — IP enrichment orchestrator.
//
// Coordinates concurrent enrichment of an IP address across all configured
// threat-intelligence vendors and assembles the unified ComplexResult / IPSimple.
//
// Vendor-specific types and mapping logic live in the integrations/ package:
//   integrations/virustotal.go  → IPVirusTotal, MapVTIPResult
//   integrations/abuseipdb.go  → IPAbuseIPDB, MapAbuseIPResult
//   integrations/threatfox.go  → TFIPResult (used directly, no extra mapping needed)
//   integrations/ipapi.go      → IPAPIResponse (fields merged into IPGeo here)
//
// Public API (unchanged):
//   NewIPProcessor(vtKey, abuseKey, ipapiKey, abusechKey) *IPProcessor
//   (*IPProcessor).Lookup(ip, mode string, useCache bool) (string, error)
//   CheckIP(raw string) ([]string, error)
package utils

import (
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

// IPSimple is the output of a simple (ipapi.is-only) lookup.
type IPSimple struct {
	IP          string  `json:"ip"`
	CompanyName string  `json:"company_name,omitempty"`
	CompanyType string  `json:"company_type,omitempty"`
	ASNOrg      string  `json:"asn_org,omitempty"`
	Country     string  `json:"country,omitempty"`
	State       string  `json:"state,omitempty"`
	City        string  `json:"city,omitempty"`
	Timezone    string  `json:"timezone,omitempty"`
	RiskLevel   string  `json:"riskLevel"`
	Links       IPLinks `json:"links"`
}

// ComplexResult is the vendor-grouped, unified output of a complex IP lookup.
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

func (p *IPProcessor) Lookup(ip, mode string, useCache bool) (string, error) {
	if strings.ToLower(mode) == "simple" {
		return p.lookupSimple(ip, useCache)
	}
	return p.lookupComplex(ip, useCache)
}

func (p *IPProcessor) lookupSimple(ip string, useCache bool) (string, error) {
	if useCache {
		if cached := getCached(ip, "IPAPIIS_IP"); cached != "" {
			return cached, nil
		}
	}
	raw, err := integrations.FetchIPAPI(ip, p.ipapiKey)
	if err != nil {
		return "", err
	}
	out := IPSimple{
		IP: raw.IP, CompanyName: raw.Company.Name, CompanyType: raw.Company.Type,
		ASNOrg: raw.ASN.Org, Country: raw.Location.Country, State: raw.Location.State,
		City: raw.Location.City, Timezone: raw.Location.Timezone,
		RiskLevel: "CLEAN", Links: newIPLinks(ip),
	}
	j, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", err
	}
	putCached(ip, string(j), "IPAPIIS_IP")
	return string(j), nil
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

func (p *IPProcessor) lookupComplex(ip string, useCache bool) (string, error) {
	abuseCh := make(chan abuseResult, 1)
	vtCh := make(chan vtIPResult, 1)
	geoCh := make(chan geoResult, 1)
	tfCh := make(chan tfIPRes, 1)

	// ── AbuseIPDB ─────────────────────────────────────────────────────────────
	go func() {
		if useCache {
			if cached := getCached(ip, "ABUSE_IP"); cached != "" {
				var out integrations.AbuseIPResult
				if err := json.Unmarshal([]byte(cached), &out); err == nil {
					abuseCh <- abuseResult{data: &out}
					return
				}
			}
		}
		d, err := integrations.FetchAbuseIP(ip, p.abuseKey)
		if err == nil && d != nil {
			if j, e := json.Marshal(d); e == nil {
				putCached(ip, string(j), "ABUSE_IP")
			}
		}
		abuseCh <- abuseResult{data: d, err: err}
	}()

	// ── VirusTotal ────────────────────────────────────────────────────────────
	go func() {
		if useCache {
			if cached := getCached(ip, "VT_IP"); cached != "" {
				var out integrations.VTIPResult
				if err := json.Unmarshal([]byte(cached), &out); err == nil {
					vtCh <- vtIPResult{data: &out}
					return
				}
			}
		}
		d, err := integrations.FetchVTIP(ip, p.vtKey)
		if err == nil && d != nil {
			if j, e := json.Marshal(d); e == nil {
				putCached(ip, string(j), "VT_IP")
			}
		}
		vtCh <- vtIPResult{data: d, err: err}
	}()

	// ── ipapi.is ──────────────────────────────────────────────────────────────
	go func() {
		d, err := integrations.FetchIPAPI(ip, p.ipapiKey)
		geoCh <- geoResult{data: d, err: err}
	}()

	// ── ThreatFox ─────────────────────────────────────────────────────────────
	go func() {
		if useCache {
			if cached := getHashCached(ip, "TF_IP"); cached != "" {
				var out integrations.TFIPResult
				if err := json.Unmarshal([]byte(cached), &out); err == nil {
					tfCh <- tfIPRes{data: &out}
					return
				}
			}
		}
		d, err := integrations.FetchTFIP(ip, p.abusechKey)
		if d != nil {
			if j, e := json.Marshal(d); e == nil {
				putHashCached(ip, string(j), "TF_IP")
			}
		}
		tfCh <- tfIPRes{data: d, err: err}
	}()

	ar := <-abuseCh
	vr := <-vtCh
	gr := <-geoCh
	tr := <-tfCh

	if ar.err != nil {
		return "", fmt.Errorf("AbuseIPDB: %w", ar.err)
	}
	if vr.err != nil {
		return "", fmt.Errorf("VirusTotal: %w", vr.err)
	}

	result := ComplexResult{
		IPAddress: ar.data.IPAddress,
		RiskLevel: assessRisk(ar.data.AbuseConfidenceScore, vr.data.Malicious),
		Links:     newIPLinks(ip),
		Geo: IPGeo{
			ISP:           ar.data.ISP,
			CountryCode:   ar.data.CountryCode,
			IsPublic:      ar.data.IsPublic,
			IsWhitelisted: ar.data.IsWhitelisted,
			Hostnames:     ar.data.Hostnames,
		},
		VirusTotal: integrations.MapVTIPResult(vr.data),
		AbuseIPDB:  integrations.MapAbuseIPResult(ar.data),
	}

	// Merge ipapi.is geo fields — these supplement what AbuseIPDB already provides.
	if gr.err == nil && gr.data != nil {
		result.Geo.Country = gr.data.Location.Country
		result.Geo.City = gr.data.Location.City
		result.Geo.State = gr.data.Location.State
		result.Geo.Timezone = gr.data.Location.Timezone
		if result.Geo.ISP == "" {
			result.Geo.ISP = gr.data.ASN.Org
		}
	}

	if tr.data != nil {
		result.ThreatFox = tr.data
	} else if tr.err != nil {
		result.ThreatFox = &integrations.TFIPResult{QueryStatus: "error"}
	}

	j, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(j), nil
}

// ── Risk assessment ───────────────────────────────────────────────────────────

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
