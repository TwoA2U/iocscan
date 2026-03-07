// utils/hashutil.go — Hash enrichment orchestrator.
//
// Coordinates concurrent enrichment of a file hash across all configured
// threat-intelligence vendors and assembles the unified HashResult.
//
// Improvements in this revision:
//   1. init() removed — hashCacheTables no longer needs to be pre-populated
//      here because allowedTables in common.go is now the single unified
//      whitelist covering both IP and hash tables.
//   2. getCacheEntry / putCacheEntry replace the old getHashCached / putHashCached
//      calls so all cache access goes through one code path.
//   3. LookupHash accepts a context.Context and threads it through to vendor
//      calls so abandoned requests cancel in-flight goroutines.
//
// Vendor-specific types and mapping logic live in the integrations/ package:
//   integrations/virustotal.go    → HashVirusTotal, VTSignerDetail, SigmaSummaryEntry, MapVTHashResult
//   integrations/malwarebazaar.go → HashMalwareBazaar, MapMBResult
//   integrations/threatfox.go     → TFHashResult (used directly, no extra mapping needed)
//
// Public API:
//   LookupHash(ctx, hash, vtKey, abusechKey string, useCache bool) (string, error)
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
	Links     HashLinks `json:"links"`

	VirusTotal    integrations.HashVirusTotal    `json:"virustotal"`
	MalwareBazaar integrations.HashMalwareBazaar `json:"malwarebazaar"`
	ThreatFox     *integrations.TFHashResult     `json:"threatfox,omitempty"`
}

// ── Orchestration helpers ─────────────────────────────────────────────────────

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

// ── LookupHash ────────────────────────────────────────────────────────────────

// LookupHash enriches a single file hash concurrently across all vendors.
// ctx is threaded through so a cancelled HTTP request aborts vendor calls.
func LookupHash(ctx context.Context, hash, vtKey, abusechKey string, useCache bool) (string, error) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	hashType := detectHashType(hash)
	if hashType == "unknown" {
		return "", fmt.Errorf("unsupported hash (expected MD5/SHA1/SHA256 hex)")
	}

	result := HashResult{
		Hash:     hash,
		HashType: hashType,
		Links: HashLinks{
			VirusTotal:    "https://www.virustotal.com/gui/file/" + hash,
			MalwareBazaar: "https://bazaar.abuse.ch/sample/" + hash,
		},
		MalwareBazaar: integrations.HashMalwareBazaar{QueryStatus: "no_api_key"},
	}

	// ── Per-vendor channel types ──────────────────────────────────────────────
	type vtRes struct {
		d   *integrations.VTFileResponse
		err error
	}
	type mbRes struct {
		d      *integrations.MBEntry
		status string
		err    error
	}
	type tfRes struct {
		data *integrations.TFHashResult
		err  error
	}

	vtCh := make(chan vtRes, 1)
	mbCh := make(chan mbRes, 1)
	tfCh := make(chan tfRes, 1)

	// ── VirusTotal ────────────────────────────────────────────────────────────
	go func() {
		if useCache {
			if raw := getCacheEntry(hash, "VT_HASH"); raw != "" {
				var r integrations.VTFileResponse
				if err := json.Unmarshal([]byte(raw), &r); err == nil {
					vtCh <- vtRes{d: &r}
					return
				}
			}
		}
		r, err := integrations.FetchVTHash(ctx, hash, vtKey)
		if err == nil && r != nil {
			if b, e := json.Marshal(r); e == nil {
				putCacheEntry(hash, string(b), "VT_HASH")
			}
		}
		vtCh <- vtRes{d: r, err: err}
	}()

	// ── MalwareBazaar ─────────────────────────────────────────────────────────
	go func() {
		if useCache {
			if raw := getCacheEntry(hash, "MB_HASH"); raw != "" {
				var e integrations.MBEntry
				if err := json.Unmarshal([]byte(raw), &e); err == nil {
					mbCh <- mbRes{d: &e, status: "ok"}
					return
				}
			}
		}
		e, status, err := integrations.FetchMBHash(ctx, hash, abusechKey)
		if err == nil && e != nil {
			if b, er := json.Marshal(e); er == nil {
				putCacheEntry(hash, string(b), "MB_HASH")
			}
		}
		mbCh <- mbRes{d: e, status: status, err: err}
	}()

	// ── ThreatFox ─────────────────────────────────────────────────────────────
	go func() {
		if useCache {
			if raw := getCacheEntry(hash, "TF_HASH"); raw != "" {
				var r integrations.TFHashResult
				if err := json.Unmarshal([]byte(raw), &r); err == nil {
					tfCh <- tfRes{data: &r}
					return
				}
			}
		}
		d, err := integrations.FetchTFHash(ctx, hash, abusechKey)
		if d != nil {
			if b, e := json.Marshal(d); e == nil {
				putCacheEntry(hash, string(b), "TF_HASH")
			}
		}
		tfCh <- tfRes{data: d, err: err}
	}()

	vr := <-vtCh
	mr := <-mbCh
	tr := <-tfCh

	// Respect context cancellation — don't marshal a result nobody will read.
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("request cancelled: %w", err)
	}

	// ── Populate VirusTotal (via integrations mapper) ─────────────────────────
	sandboxMal := 0
	if vr.d != nil {
		result.VirusTotal, sandboxMal = integrations.MapVTHashResult(vr.d)

		// Upgrade links to canonical SHA256 once we have the full response.
		if result.VirusTotal.SHA256 != "" {
			result.Links.VirusTotal = "https://www.virustotal.com/gui/file/" + result.VirusTotal.SHA256
			result.Links.MalwareBazaar = "https://bazaar.abuse.ch/sample/" + result.VirusTotal.SHA256
		}
	}

	// ── Populate MalwareBazaar (via integrations mapper) ─────────────────────
	result.MalwareBazaar = integrations.MapMBResult(mr.d, mr.status)

	// ── Populate ThreatFox ────────────────────────────────────────────────────
	if tr.data != nil {
		result.ThreatFox = tr.data
	} else if tr.err != nil {
		result.ThreatFox = &integrations.TFHashResult{QueryStatus: "error"}
	}

	result.RiskLevel = assessHashRisk(
		result.VirusTotal.Malicious,
		mr.status == "ok" && mr.d != nil,
		sandboxMal,
	)

	j, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(j), nil
}
