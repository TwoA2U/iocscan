// utils/iputil.go — IP enrichment types and helpers.
//
// Lookup() has moved to iputil_shim.go which delegates to the generic
// Scan() orchestrator. This file retains the output types (ComplexResult,
// IPGeo, IPLinks) and helpers (CheckIP, assessRisk, newIPLinks) that are
// still referenced by iputil_shim.go and the rest of the utils package.
package utils

import (
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

type VendorDiagnostic struct {
	Cache  string `json:"cache"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// ComplexResult is the vendor-grouped, unified output of an IP lookup.
type ComplexResult struct {
	IPAddress   string                      `json:"ipAddress"`
	RiskLevel   string                      `json:"riskLevel"`
	Cached      bool                        `json:"cached"`
	CacheHits   map[string]bool             `json:"cacheHits,omitempty"`
	Diagnostics map[string]VendorDiagnostic `json:"diagnostics,omitempty"`
	Links       IPLinks                     `json:"links"`

	Geo        IPGeo                     `json:"geo"`
	VirusTotal integrations.IPVirusTotal `json:"virustotal"`
	AbuseIPDB  integrations.IPAbuseIPDB  `json:"abuseipdb"`
	ThreatFox  *integrations.TFIPResult  `json:"threatfox,omitempty"`
	GreyNoise  *GNResult                 `json:"greynoise,omitempty"`
}

// GNResult holds GreyNoise enrichment fields in an IP scan result.
type GNResult struct {
	Classification string `json:"classification,omitempty"`
	Noise          bool   `json:"noise"`
	Riot           bool   `json:"riot"`
	Name           string `json:"name,omitempty"`
	LastSeen       string `json:"lastSeen,omitempty"`
	NotObserved    bool   `json:"notObserved,omitempty"`
	Error          string `json:"error,omitempty"`
}

// ── IPProcessor ───────────────────────────────────────────────────────────────

type IPProcessor struct {
	vtKey        string
	abuseKey     string
	ipapiKey     string
	abusechKey   string
	greynoiseKey string
}

func NewIPProcessor(vtKey, abuseKey, ipapiKey, abusechKey, greynoiseKey string) *IPProcessor {
	return &IPProcessor{
		vtKey:        vtKey,
		abuseKey:     abuseKey,
		ipapiKey:     ipapiKey,
		abusechKey:   abusechKey,
		greynoiseKey: greynoiseKey,
	}
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

// assessRisk computes the overall risk level from AbuseIPDB and VT signals.
// Still used by legacy code paths; new code uses EvaluateRisk from manifests.
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
