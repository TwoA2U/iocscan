// utils/hashutil_shim.go — Backward-compatible hash enrichment shim.
//
// LookupHash() now delegates to Scan() and re-shapes the ScanResult into the
// existing HashResult JSON structure so /api/scan/hash callers see zero change
// in response format.
//
// The original hashutil.go is preserved intact; this file replaces only
// the fan-out section. assessHashRisk() in hashutil.go is no longer called
// from this path — risk is now computed by evaluateOverallRisk() in the
// orchestrator, which reads each manifest's RiskRules. The function remains
// in hashutil.go to avoid breaking any code that imports it directly.
//
// Once the frontend is fully migrated (Phase 7 + Phase 8) this shim can
// be removed and hashutil.go retired.
package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/TwoA2U/iocscan/integrations"
)

// LookupHash enriches a single file hash via the generic orchestrator and
// returns the result as a HashResult-shaped JSON string for backward
// compatibility with /api/scan/hash.
func LookupHash(ctx context.Context, hash, vtKey, abusechKey string, useCache bool) (string, error) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	hashType := detectHashType(hash)
	if hashType == "unknown" {
		return "", fmt.Errorf("unsupported hash (expected MD5/SHA1/SHA256 hex)")
	}

	keys := BuildKeys(vtKey, "", "", abusechKey)

	sr, err := Scan(ctx, hash, integrations.IOCTypeHash, keys, useCache)
	if err != nil {
		return "", err
	}

	result := buildHashResult(hash, hashType, sr)

	// Cached = true when every integration served from local cache.
	result.Cached = len(sr.CacheHits) > 0 && len(sr.CacheHits) == len(sr.Results)

	j, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal HashResult: %w", err)
	}
	return string(j), nil
}

// buildHashResult re-shapes a ScanResult into the HashResult structure
// so the existing /api/scan/hash response format is unchanged.
func buildHashResult(hash, hashType string, sr *ScanResult) HashResult {
	result := HashResult{
		Hash:      hash,
		HashType:  hashType,
		RiskLevel: sr.RiskLevel,
		Links: HashLinks{
			VirusTotal:    "https://www.virustotal.com/gui/file/" + hash,
			MalwareBazaar: "https://bazaar.abuse.ch/sample/" + hash,
		},
		MalwareBazaar: integrations.HashMalwareBazaar{QueryStatus: "no_results"},
	}

	// ── VirusTotal ────────────────────────────────────────────────────────────
	if f, ok := sr.Results["virustotal_hash"]; ok {
		vt := integrations.HashVirusTotal{
			MD5:                  strField(f, "md5"),
			SHA1:                 strField(f, "sha1"),
			SHA256:               strField(f, "sha256"),
			MeaningfulName:       strField(f, "meaningfulName"),
			Magic:                strField(f, "magic"),
			Magika:               strField(f, "magika"),
			Malicious:            intField(f, "malicious"),
			Suspicious:           intField(f, "suspicious"),
			Harmless:             intField(f, "harmless"),
			Undetected:           intField(f, "undetected"),
			Reputation:           intField(f, "reputation"),
			SuggestedThreatLabel: strField(f, "suggestedThreatLabel"),
			SignatureSigners:     strField(f, "signatureSigners"),
		}
		if v, ok := f["popularThreatNames"]; ok {
			vt.PopularThreatNames = toStringSlice(v)
		}
		if v, ok := f["popularThreatCategories"]; ok {
			vt.PopularThreatCategories = toStringSlice(v)
		}
		if v, ok := f["sandboxMalwareClassifications"]; ok {
			vt.SandboxMalwareClassifications = toStringSlice(v)
		}
		// Sigma analysis summary — stored as map[string]SigmaSummaryEntry
		if v, ok := f["sigmaAnalysisSummary"]; ok {
			if raw, err := json.Marshal(v); err == nil {
				var sigma map[string]integrations.SigmaSummaryEntry
				if json.Unmarshal(raw, &sigma) == nil {
					vt.SigmaAnalysisSummary = sigma
				}
			}
		}
		// Signer detail
		status := strField(f, "signerStatus")
		if status != "" {
			vt.SignerDetail = &integrations.VTSignerDetail{
				Status:     status,
				Name:       strField(f, "signerName"),
				CertIssuer: strField(f, "signerCertIssuer"),
				ValidFrom:  strField(f, "signerValidFrom"),
				ValidTo:    strField(f, "signerValidTo"),
			}
		}
		// Upgrade links to SHA256 once we have it from VT
		if vt.SHA256 != "" {
			result.Links.VirusTotal = "https://www.virustotal.com/gui/file/" + vt.SHA256
			result.Links.MalwareBazaar = "https://bazaar.abuse.ch/sample/" + vt.SHA256
		}
		result.VirusTotal = vt
	}

	// ── MalwareBazaar ─────────────────────────────────────────────────────────
	if f, ok := sr.Results["malwarebazaar"]; ok {
		mb := integrations.HashMalwareBazaar{
			QueryStatus: strField(f, "queryStatus"),
			FileName:    strField(f, "fileName"),
			FileType:    strField(f, "fileType"),
			Signature:   strField(f, "signature"),
			Comment:     strField(f, "comment"),
		}
		if v, ok := f["tags"]; ok {
			mb.Tags = toStringSlice(v)
		}
		result.MalwareBazaar = mb
	} else if errMsg, hasErr := sr.Errors["malwarebazaar"]; hasErr {
		result.MalwareBazaar = integrations.HashMalwareBazaar{QueryStatus: errMsg}
	}

	// ── ThreatFox ─────────────────────────────────────────────────────────────
	if f, ok := sr.Results["threatfox_hash"]; ok {
		qs := strField(f, "queryStatus")
		tf := &integrations.TFHashResult{QueryStatus: qs}
		if qs == "ok" {
			entry := integrations.TFHashEntry{
				Malware:         strField(f, "malware"),
				ConfidenceLevel: intField(f, "confidenceLevel"),
			}
			if tags, ok := f["tags"]; ok {
				entry.Tags = toStringSlice(tags)
			}
			tf.IOCs = []integrations.TFHashEntry{entry}
		}
		result.ThreatFox = tf
	} else if _, hasErr := sr.Errors["threatfox_hash"]; hasErr {
		result.ThreatFox = &integrations.TFHashResult{QueryStatus: "error"}
	}

	return result
}
