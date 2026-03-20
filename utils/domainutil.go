// utils/domainutil.go — Domain enrichment types and LookupDomain orchestrator.
//
// Follows the same pattern as iputil_shim.go:
//   LookupDomain() → Scan() → DomainResult (backward-compatible JSON)
//
// Supported integrations (auto-selected by registry.ForIOCType):
//   virustotal_domain  — multi-engine verdict, reputation, registrar, categories
//   threatfox_domain   — C2/botnet IOC intelligence
//
// Public API:
//   LookupDomain(ctx, domain, vtKey, abusechKey string, useCache bool) (string, error)
package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/TwoA2U/iocscan/integrations"
)

// ── Output types ──────────────────────────────────────────────────────────────

// DomainLinks holds direct URLs to third-party pages for a domain.
type DomainLinks struct {
	VirusTotal string `json:"virustotal"`
	ThreatFox  string `json:"threatfox"`
}

// DomainVT holds VirusTotal enrichment fields for a domain result.
type DomainVT struct {
	Malicious            int      `json:"malicious"`
	Suspicious           int      `json:"suspicious"`
	Harmless             int      `json:"harmless"`
	Undetected           int      `json:"undetected"`
	Reputation           int      `json:"reputation"`
	SuggestedThreatLabel string   `json:"suggestedThreatLabel,omitempty"`
	Registrar            string   `json:"registrar,omitempty"`
	Categories           []string `json:"categories,omitempty"`
	ARecords             []string `json:"aRecords,omitempty"`
	CreationDate         string   `json:"creationDate,omitempty"`
	Error                string   `json:"error,omitempty"`
}

// DomainResult is the unified output of a domain lookup.
type DomainResult struct {
	Domain    string      `json:"domain"`
	RiskLevel string      `json:"riskLevel"`
	Cached    bool        `json:"cached"`
	Links     DomainLinks `json:"links"`

	VirusTotal integrations.IPVirusTotal `json:"virustotal"` // reuse IP VT type (same fields)
	VTDomain   DomainVT                  `json:"vtDomain"`   // domain-specific VT fields
	ThreatFox  *integrations.TFIPResult  `json:"threatfox,omitempty"`
}

// ── LookupDomain ─────────────────────────────────────────────────────────────

// LookupDomain enriches a single domain concurrently across all domain
// integrations and returns a backward-compatible JSON string.
func LookupDomain(ctx context.Context, domain, vtKey, abusechKey string, useCache bool) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	domain = strings.ToLower(strings.TrimSpace(domain))

	keys := BuildKeys(vtKey, "", "", abusechKey)

	sr, err := Scan(ctx, domain, integrations.IOCTypeDomain, keys, useCache)
	if err != nil {
		return "", err
	}

	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("request cancelled: %w", err)
	}

	result := buildDomainResult(domain, sr)

	// Cached = true when every integration served from local cache.
	result.Cached = len(sr.CacheHits) > 0 && len(sr.CacheHits) == len(sr.Results)

	j, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal DomainResult: %w", err)
	}
	return string(j), nil
}

// buildDomainResult reshapes a ScanResult into the DomainResult structure.
func buildDomainResult(domain string, sr *ScanResult) DomainResult {
	result := DomainResult{
		Domain:    domain,
		RiskLevel: sr.RiskLevel,
		Links: DomainLinks{
			VirusTotal: "https://www.virustotal.com/gui/domain/" + domain,
			ThreatFox:  "https://threatfox.abuse.ch/browse.php?search=ioc%3A" + domain,
		},
	}

	// ── VirusTotal domain fields ───────────────────────────────────────────────
	if f, ok := sr.Results["virustotal_domain"]; ok {
		result.VTDomain = DomainVT{
			Malicious:            intField(f, "malicious"),
			Suspicious:           intField(f, "suspicious"),
			Harmless:             intField(f, "harmless"),
			Undetected:           intField(f, "undetected"),
			Reputation:           intField(f, "reputation"),
			SuggestedThreatLabel: strField(f, "suggestedThreatLabel"),
			Registrar:            strField(f, "registrar"),
			Categories:           toStringSlice(f["categories"]),
			ARecords:             toStringSlice(f["aRecords"]),
			CreationDate:         strField(f, "creationDate"),
		}
		// Also populate the top-level VirusTotal field for table column compatibility
		result.VirusTotal = integrations.IPVirusTotal{
			Malicious:  result.VTDomain.Malicious,
			Suspicious: result.VTDomain.Suspicious,
			Harmless:   result.VTDomain.Harmless,
			Undetected: result.VTDomain.Undetected,
			Reputation: result.VTDomain.Reputation,
		}
	} else if errMsg, hasErr := sr.Errors["virustotal_domain"]; hasErr {
		result.VTDomain = DomainVT{Error: errMsg}
		result.VirusTotal = integrations.IPVirusTotal{Error: errMsg}
	}

	// ── ThreatFox ─────────────────────────────────────────────────────────────
	if f, ok := sr.Results["threatfox_domain"]; ok {
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
	} else if _, hasErr := sr.Errors["threatfox_domain"]; hasErr {
		result.ThreatFox = &integrations.TFIPResult{QueryStatus: "error"}
	}

	return result
}

// assessDomainRisk computes risk level from VT malicious count.
// Called as a fallback if EvaluateRisk returns CLEAN.
func assessDomainRisk(vtMalicious int) string {
	switch {
	case vtMalicious >= 5:
		return "CRITICAL"
	case vtMalicious >= 2:
		return "HIGH"
	case vtMalicious >= 1:
		return "MEDIUM"
	default:
		return "CLEAN"
	}
}

// epochToDate is defined in hashutil.go — shared across the utils package.
// Declared here as documentation; the actual implementation is in hashutil.go.
var _ = time.Unix // ensure time import is used
