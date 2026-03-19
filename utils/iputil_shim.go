// utils/iputil_shim.go — Backward-compatible IP enrichment shim.
//
// IPProcessor.Lookup() now delegates to Scan() and re-shapes the ScanResult
// into the existing ComplexResult JSON structure so /api/scan callers see
// zero change in response format.
//
// The original iputil.go is preserved intact above; only the lookupComplex()
// implementation is replaced here. assessRisk() remains in iputil.go and is
// still called from this shim for the ComplexResult path.
//
// Once the frontend is fully migrated to consume ScanResult directly
// (Phase 7 + Phase 8), this shim can be removed and iputil.go retired.
package utils

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/TwoA2U/iocscan/integrations"
)

// Lookup enriches a single IP address via the generic orchestrator and
// returns the result as a ComplexResult-shaped JSON string for backward
// compatibility with /api/scan.
func (p *IPProcessor) Lookup(ctx context.Context, ip string, useCache bool) (string, error) {
	keys := BuildKeys(p.vtKey, p.abuseKey, p.ipapiKey, p.abusechKey)

	sr, err := Scan(ctx, ip, integrations.IOCTypeIP, keys, useCache)
	if err != nil {
		return "", err
	}

	result := buildComplexResult(ip, sr)

	j, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal ComplexResult: %w", err)
	}
	return string(j), nil
}

// buildComplexResult re-shapes a ScanResult into the ComplexResult structure
// so the existing /api/scan response format is unchanged for frontend consumers.
func buildComplexResult(ip string, sr *ScanResult) ComplexResult {
	result := ComplexResult{
		IPAddress: ip,
		RiskLevel: sr.RiskLevel,
		Links:     newIPLinks(ip),
	}

	// ── AbuseIPDB ─────────────────────────────────────────────────────────────
	if f, ok := sr.Results["abuseipdb"]; ok {
		// Use the canonical IP address from AbuseIPDB response when available.
		if canonical := strField(f, "ipAddress"); canonical != "" {
			result.IPAddress = canonical
			result.Links = newIPLinks(canonical)
		}
		result.AbuseIPDB = integrations.IPAbuseIPDB{
			ConfidenceScore: intField(f, "confidenceScore"),
			TotalReports:    intField(f, "totalReports"),
			LastReportedAt:  strField(f, "lastReportedAt"),
		}
		// Populate geo from AbuseIPDB fields (ISP, countryCode, hostnames)
		result.Geo.ISP = strField(f, "isp")
		result.Geo.CountryCode = strField(f, "countryCode")
		result.Geo.IsPublic = boolField(f, "isPublic")
		result.Geo.IsWhitelisted = boolField(f, "isWhitelisted")
		if hn, ok := f["hostnames"]; ok {
			result.Geo.Hostnames = toStringSlice(hn)
		}
	} else if errMsg, hasErr := sr.Errors["abuseipdb"]; hasErr {
		result.AbuseIPDB = integrations.IPAbuseIPDB{Error: errMsg}
	}

	// ── ipapi.is ──────────────────────────────────────────────────────────────
	if f, ok := sr.Results["ipapi"]; ok {
		result.Geo.Country = strField(f, "country")
		result.Geo.City = strField(f, "city")
		result.Geo.State = strField(f, "state")
		result.Geo.Timezone = strField(f, "timezone")
		// ipapi.is ASN org fills ISP if AbuseIPDB didn't provide one
		if result.Geo.ISP == "" {
			result.Geo.ISP = strField(f, "org")
		}
	}

	// ── VirusTotal ────────────────────────────────────────────────────────────
	if f, ok := sr.Results["virustotal_ip"]; ok {
		result.VirusTotal = integrations.IPVirusTotal{
			Malicious:  intField(f, "malicious"),
			Suspicious: intField(f, "suspicious"),
			Undetected: intField(f, "undetected"),
			Harmless:   intField(f, "harmless"),
			Reputation: intField(f, "reputation"),
		}
	} else if errMsg, hasErr := sr.Errors["virustotal_ip"]; hasErr {
		result.VirusTotal = integrations.IPVirusTotal{Error: errMsg}
	}

	// ── ThreatFox ─────────────────────────────────────────────────────────────
	if f, ok := sr.Results["threatfox_ip"]; ok {
		tf := &integrations.TFIPResult{
			QueryStatus:     strField(f, "queryStatus"),
			ThreatType:      strField(f, "threatType"),
			Malware:         strField(f, "malware"),
			MalwareAlias:    strField(f, "malwareAlias"),
			ConfidenceLevel: intField(f, "confidenceLevel"),
			FirstSeen:       strField(f, "firstSeen"),
			LastSeen:        strField(f, "lastSeen"),
			Reporter:        strField(f, "reporter"),
		}
		if tags, ok := f["tags"]; ok {
			tf.Tags = toStringSlice(tags)
		}
		result.ThreatFox = tf
	} else if _, hasErr := sr.Errors["threatfox_ip"]; hasErr {
		result.ThreatFox = &integrations.TFIPResult{QueryStatus: "error"}
	}

	return result
}

// ── Field extraction helpers ──────────────────────────────────────────────────
// These convert map[string]any values to typed Go values safely.
// They mirror how the existing code accessed typed struct fields
// but work on the generic fields map returned by integrations.

func strField(f map[string]any, key string) string {
	if v, ok := f[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func intField(f map[string]any, key string) int {
	if v, ok := f[key]; ok {
		if n, ok := toInt(v); ok {
			return n
		}
	}
	return 0
}

func boolField(f map[string]any, key string) bool {
	if v, ok := f[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func toStringSlice(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

// toInt is re-declared here because orchestrator.go is in the same package
// and Go does not allow duplicate declarations — this note is intentional.
// The actual toInt lives in orchestrator.go and is shared across the package.
