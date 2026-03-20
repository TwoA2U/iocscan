// utils/hashutil.go — Hash enrichment helpers.
//
// LookupHash() has moved to hashutil_shim.go which delegates to the generic
// Scan() orchestrator. This file retains the output types (HashResult, HashLinks)
// and helper functions (detectHashType, epochToDate, assessHashRisk) that are
// still referenced by hashutil_shim.go and the rest of the utils package.
package utils

import (
	"time"

	"github.com/TwoA2U/iocscan/integrations"
)

// ── Output types ──────────────────────────────────────────────────────────────

// HashLinks holds direct URLs to third-party pages for a hash.
type HashLinks struct {
	VirusTotal    string `json:"virustotal"`
	MalwareBazaar string `json:"malwarebazaar"`
}

// HashResult is the vendor-grouped, unified output of a hash lookup.
// Vendor-specific sub-structs are defined in their respective integrations/ files.
type HashResult struct {
	Hash      string    `json:"hash"`
	HashType  string    `json:"hashType"`
	RiskLevel string    `json:"riskLevel"`
	Cached    bool      `json:"cached"`
	Links     HashLinks `json:"links"`

	VirusTotal    integrations.HashVirusTotal    `json:"virustotal"`
	MalwareBazaar integrations.HashMalwareBazaar `json:"malwarebazaar"`
	ThreatFox     *integrations.TFHashResult     `json:"threatfox,omitempty"`
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func detectHashType(h string) string {
	switch len(h) {
	case 32:
		return "MD5"
	case 40:
		return "SHA1"
	case 64:
		return "SHA256"
	default:
		return "unknown"
	}
}

func epochToDate(epoch int64) string {
	if epoch == 0 {
		return ""
	}
	return time.Unix(epoch, 0).UTC().Format("2006-01-02 15:04:05")
}

func assessHashRisk(vtMal int, mbFound bool, sandboxMal int) string {
	switch {
	case vtMal >= 15 || sandboxMal >= 5:
		return "CRITICAL"
	case vtMal >= 5 || (vtMal >= 1 && mbFound):
		return "HIGH"
	case vtMal >= 1 || mbFound || sandboxMal >= 1:
		return "MEDIUM"
	default:
		return "CLEAN"
	}
}
