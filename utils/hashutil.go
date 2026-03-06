// utils/hashutil.go — Hash enrichment orchestrator.
//
// Public API (unchanged):
//   LookupHash(hash, vtKey, abusechKey string, useCache bool) (string, error)
package utils

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/TwoA2U/iocscan/integrations"
)

// ── Sub-structs for vendor-grouped output ─────────────────────────────────────

// VTSignerDetail holds code-signing certificate detail.
type VTSignerDetail struct {
	CertIssuer string `json:"certIssuer,omitempty"`
	Name       string `json:"name,omitempty"`
	Status     string `json:"status,omitempty"`
	ValidFrom  string `json:"validFrom,omitempty"`
	ValidTo    string `json:"validTo,omitempty"`
}

// SigmaSummaryEntry holds sigma rule hit counts per ruleset.
type SigmaSummaryEntry struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// HashLinks holds direct URLs to third-party pages for a hash.
type HashLinks struct {
	VirusTotal    string `json:"virustotal"`
	MalwareBazaar string `json:"malwarebazaar"`
}

// HashVirusTotal holds all VirusTotal enrichment fields for a file hash.
type HashVirusTotal struct {
	// File identity
	MD5            string `json:"md5,omitempty"`
	SHA1           string `json:"sha1,omitempty"`
	SHA256         string `json:"sha256,omitempty"`
	MeaningfulName string `json:"meaningfulName,omitempty"`
	Magic          string `json:"magic,omitempty"`
	Magika         string `json:"magika,omitempty"`

	// Detection stats
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Harmless   int `json:"harmless"`
	Undetected int `json:"undetected"`
	Reputation int `json:"reputation"`

	// Threat classification
	SuggestedThreatLabel    string   `json:"suggestedThreatLabel,omitempty"`
	PopularThreatCategories []string `json:"popularThreatCategories,omitempty"`
	PopularThreatNames      []string `json:"popularThreatNames,omitempty"`

	// Sandbox
	SandboxMalwareClassifications []string `json:"sandboxMalwareClassifications,omitempty"`

	// Sigma
	SigmaAnalysisSummary map[string]SigmaSummaryEntry `json:"sigmaAnalysisSummary,omitempty"`

	// Code signing
	SignatureSigners string          `json:"signatureSigners,omitempty"`
	SignerDetail     *VTSignerDetail `json:"signerDetail,omitempty"`
}

// HashMalwareBazaar holds MalwareBazaar enrichment for a file hash.
type HashMalwareBazaar struct {
	QueryStatus string   `json:"queryStatus"`
	FileName    string   `json:"fileName,omitempty"`
	FileType    string   `json:"fileType,omitempty"`
	Signature   string   `json:"signature,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Comment     string   `json:"comment,omitempty"`
}

// HashResult is the vendor-grouped output of a hash lookup.
type HashResult struct {
	Hash      string    `json:"hash"`
	HashType  string    `json:"hashType"`
	RiskLevel string    `json:"riskLevel"`
	Links     HashLinks `json:"links"`

	VirusTotal    HashVirusTotal             `json:"virustotal"`
	MalwareBazaar HashMalwareBazaar          `json:"malwarebazaar"`
	ThreatFox     *integrations.TFHashResult `json:"threatfox,omitempty"`
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

// ── cache table registration ──────────────────────────────────────────────────

func init() {
	hashCacheTables["VT_HASH"] = true
	hashCacheTables["MB_HASH"] = true
	hashCacheTables["TF_IP"] = true
	hashCacheTables["TF_HASH"] = true
}

// ── LookupHash ────────────────────────────────────────────────────────────────

func LookupHash(hash, vtKey, abusechKey string, useCache bool) (string, error) {
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
		MalwareBazaar: HashMalwareBazaar{QueryStatus: "no_api_key"},
	}

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
			if raw := getHashCached(hash, "VT_HASH"); raw != "" {
				var r integrations.VTFileResponse
				if err := json.Unmarshal([]byte(raw), &r); err == nil {
					vtCh <- vtRes{d: &r}
					return
				}
			}
		}
		r, err := integrations.FetchVTHash(hash, vtKey)
		if err == nil && r != nil {
			if b, e := json.Marshal(r); e == nil {
				putHashCached(hash, string(b), "VT_HASH")
			}
		}
		vtCh <- vtRes{d: r, err: err}
	}()

	// ── MalwareBazaar ─────────────────────────────────────────────────────────
	go func() {
		if useCache {
			if raw := getHashCached(hash, "MB_HASH"); raw != "" {
				var e integrations.MBEntry
				if err := json.Unmarshal([]byte(raw), &e); err == nil {
					mbCh <- mbRes{d: &e, status: "ok"}
					return
				}
			}
		}
		e, status, err := integrations.FetchMBHash(hash, abusechKey)
		if err == nil && e != nil {
			if b, er := json.Marshal(e); er == nil {
				putHashCached(hash, string(b), "MB_HASH")
			}
		}
		mbCh <- mbRes{d: e, status: status, err: err}
	}()

	// ── ThreatFox ─────────────────────────────────────────────────────────────
	go func() {
		if useCache {
			if raw := getHashCached(hash, "TF_HASH"); raw != "" {
				var r integrations.TFHashResult
				if err := json.Unmarshal([]byte(raw), &r); err == nil {
					tfCh <- tfRes{data: &r}
					return
				}
			}
		}
		d, err := integrations.FetchTFHash(hash, abusechKey)
		if d != nil {
			if b, e := json.Marshal(d); e == nil {
				putHashCached(hash, string(b), "TF_HASH")
			}
		}
		tfCh <- tfRes{data: d, err: err}
	}()

	vr := <-vtCh
	mr := <-mbCh
	tr := <-tfCh

	// ── Populate VirusTotal ───────────────────────────────────────────────────
	sandboxMal := 0
	if vr.d != nil {
		a := vr.d.Data.Attributes
		result.VirusTotal.MD5 = a.MD5
		result.VirusTotal.SHA1 = a.SHA1
		result.VirusTotal.SHA256 = a.SHA256
		result.VirusTotal.MeaningfulName = a.MeaningfulName
		result.VirusTotal.Magic = a.Magic
		result.VirusTotal.Magika = a.Magika
		result.VirusTotal.Malicious = a.LastAnalysisStats.Malicious
		result.VirusTotal.Suspicious = a.LastAnalysisStats.Suspicious
		result.VirusTotal.Harmless = a.LastAnalysisStats.Harmless
		result.VirusTotal.Undetected = a.LastAnalysisStats.Undetected
		result.VirusTotal.Reputation = a.Reputation
		result.VirusTotal.SuggestedThreatLabel = a.PopularThreatClassification.SuggestedThreatLabel

		for _, c := range a.PopularThreatClassification.PopularThreatCategory {
			result.VirusTotal.PopularThreatCategories = append(result.VirusTotal.PopularThreatCategories, c.Value)
		}
		for _, n := range a.PopularThreatClassification.PopularThreatName {
			result.VirusTotal.PopularThreatNames = append(result.VirusTotal.PopularThreatNames, n.Value)
		}

		seen := map[string]bool{}
		for _, sv := range a.SandboxVerdicts {
			if sv.Category == "malicious" {
				sandboxMal++
				for _, mc := range sv.MalwareClassification {
					if !seen[mc] {
						result.VirusTotal.SandboxMalwareClassifications = append(result.VirusTotal.SandboxMalwareClassifications, mc)
						seen[mc] = true
					}
				}
			}
		}

		if len(a.SigmaAnalysisSummary) > 0 {
			result.VirusTotal.SigmaAnalysisSummary = make(map[string]SigmaSummaryEntry)
			for ruleset, stats := range a.SigmaAnalysisSummary {
				result.VirusTotal.SigmaAnalysisSummary[ruleset] = SigmaSummaryEntry{
					Critical: stats.Critical, High: stats.High, Medium: stats.Medium, Low: stats.Low,
				}
			}
		}

		result.VirusTotal.SignatureSigners = a.SignatureInfo.Signers
		if len(a.SignatureInfo.SignersDetails) > 0 {
			d := a.SignatureInfo.SignersDetails[0]
			result.VirusTotal.SignerDetail = &VTSignerDetail{
				CertIssuer: d.CertIssuer, Name: d.Name, Status: d.Status,
				ValidFrom: d.ValidFrom, ValidTo: d.ValidTo,
			}
		}

		// Upgrade links to canonical SHA256
		if a.SHA256 != "" {
			result.Links.VirusTotal = "https://www.virustotal.com/gui/file/" + a.SHA256
			result.Links.MalwareBazaar = "https://bazaar.abuse.ch/sample/" + a.SHA256
		}
	}

	// ── Populate MalwareBazaar ────────────────────────────────────────────────
	result.MalwareBazaar.QueryStatus = mr.status
	if mr.d != nil {
		result.MalwareBazaar.FileName = mr.d.FileName
		result.MalwareBazaar.FileType = mr.d.FileType
		result.MalwareBazaar.Signature = mr.d.Signature
		result.MalwareBazaar.Tags = mr.d.Tags
		result.MalwareBazaar.Comment = mr.d.Comment
	}

	// ── Populate ThreatFox ────────────────────────────────────────────────────
	if tr.data != nil {
		result.ThreatFox = tr.data
	} else if tr.err != nil {
		result.ThreatFox = &integrations.TFHashResult{QueryStatus: "error"}
	}

	result.RiskLevel = assessHashRisk(result.VirusTotal.Malicious, mr.status == "ok" && mr.d != nil, sandboxMal)

	j, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(j), nil
}
