// integrations/virustotal.go — VirusTotal enrichment for IP addresses and file hashes.
//
// API docs: https://developers.virustotal.com/reference/overview
//
// IP lookup:   GET https://www.virustotal.com/api/v3/ip_addresses/{ip}
// Hash lookup: GET https://www.virustotal.com/api/v3/files/{hash}
//
// Auth: x-apikey header (required).
//
// This file owns:
//   - Raw API response types (VTIPResponse, VTFileResponse, VTFileAttr)
//   - Cleaned output types (VTIPResult, IPVirusTotal, HashVirusTotal, VTSignerDetail, SigmaSummaryEntry)
//   - Fetch functions (FetchVTIP, FetchVTHash)
//   - Mapping functions (MapVTIPResult, MapVTHashResult)
package integrations

import (
	"encoding/json"
	"fmt"

	"github.com/TwoA2U/iocscan/internal/httpclient"
)

const (
	vtEndpointIP   = "https://www.virustotal.com/api/v3/ip_addresses/"
	vtEndpointHash = "https://www.virustotal.com/api/v3/files/"
)

// ── Raw API response types ────────────────────────────────────────────────────

// VTIPResponse is the raw API response for an IP address lookup.
type VTIPResponse struct {
	Data struct {
		ID         string `json:"id"`
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Harmless   int `json:"harmless"`
			} `json:"last_analysis_stats"`
			Reputation int `json:"reputation"`
		} `json:"attributes"`
	} `json:"data"`
}

// VTFileAttr holds the full attributes block from a VT file response.
type VTFileAttr struct {
	MD5            string `json:"md5"`
	SHA1           string `json:"sha1"`
	SHA256         string `json:"sha256"`
	MeaningfulName string `json:"meaningful_name"`
	Magic          string `json:"magic"`
	Magika         string `json:"magika"`

	LastAnalysisStats struct {
		Harmless   int `json:"harmless"`
		Malicious  int `json:"malicious"`
		Suspicious int `json:"suspicious"`
		Undetected int `json:"undetected"`
	} `json:"last_analysis_stats"`

	Reputation int `json:"reputation"`

	PopularThreatClassification struct {
		SuggestedThreatLabel  string `json:"suggested_threat_label"`
		PopularThreatCategory []struct {
			Value string `json:"value"`
			Count int    `json:"count"`
		} `json:"popular_threat_category"`
		PopularThreatName []struct {
			Value string `json:"value"`
			Count int    `json:"count"`
		} `json:"popular_threat_name"`
	} `json:"popular_threat_classification"`

	SandboxVerdicts map[string]struct {
		Category              string   `json:"category"`
		MalwareClassification []string `json:"malware_classification"`
		SandboxName           string   `json:"sandbox_name"`
	} `json:"sandbox_verdicts"`

	SigmaAnalysisSummary map[string]struct {
		Critical int `json:"critical"`
		High     int `json:"high"`
		Medium   int `json:"medium"`
		Low      int `json:"low"`
	} `json:"sigma_analysis_summary"`

	SignatureInfo struct {
		Signers        string `json:"signers"`
		SignersDetails []struct {
			CertIssuer string `json:"cert issuer"`
			Name       string `json:"name"`
			Status     string `json:"status"`
			ValidFrom  string `json:"valid from"`
			ValidTo    string `json:"valid to"`
			Algorithm  string `json:"algorithm"`
		} `json:"signers details"`
	} `json:"signature_info"`
}

// VTFileResponse is the raw API response for a file/hash lookup.
type VTFileResponse struct {
	Data struct {
		Attributes VTFileAttr `json:"attributes"`
	} `json:"data"`
}

// ── Cleaned output types ──────────────────────────────────────────────────────

// VTIPResult holds the cleaned VT enrichment for an IP address (internal cache type).
type VTIPResult struct {
	IPAddress  string `json:"ipAddress"`
	Malicious  int    `json:"malicious"`
	Suspicious int    `json:"suspicious"`
	Undetected int    `json:"undetected"`
	Harmless   int    `json:"harmless"`
	Reputation int    `json:"reputation"`
}

// IPVirusTotal holds the VirusTotal enrichment fields surfaced in an IP scan result.
type IPVirusTotal struct {
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Undetected int `json:"undetected"`
	Harmless   int `json:"harmless"`
	Reputation int `json:"reputation"`
}

// VTSignerDetail holds code-signing certificate detail for a file hash result.
type VTSignerDetail struct {
	CertIssuer string `json:"certIssuer,omitempty"`
	Name       string `json:"name,omitempty"`
	Status     string `json:"status,omitempty"`
	ValidFrom  string `json:"validFrom,omitempty"`
	ValidTo    string `json:"validTo,omitempty"`
}

// SigmaSummaryEntry holds sigma rule hit counts per ruleset for a file hash result.
type SigmaSummaryEntry struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// HashVirusTotal holds all VirusTotal enrichment fields for a file hash result.
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

// ── Fetch functions ───────────────────────────────────────────────────────────

// FetchVTIP queries VirusTotal for an IP address.
func FetchVTIP(ip, apiKey string) (*VTIPResult, error) {
	body, err := httpclient.DoGet(vtEndpointIP+ip, map[string]string{"x-apikey": apiKey})
	if err != nil {
		return nil, fmt.Errorf("VT IP: %w", err)
	}

	var resp VTIPResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("VT IP parse: %w", err)
	}

	return &VTIPResult{
		IPAddress:  resp.Data.ID,
		Malicious:  resp.Data.Attributes.LastAnalysisStats.Malicious,
		Suspicious: resp.Data.Attributes.LastAnalysisStats.Suspicious,
		Undetected: resp.Data.Attributes.LastAnalysisStats.Undetected,
		Harmless:   resp.Data.Attributes.LastAnalysisStats.Harmless,
		Reputation: resp.Data.Attributes.Reputation,
	}, nil
}

// FetchVTHash queries VirusTotal for a file hash (MD5, SHA1, or SHA256).
func FetchVTHash(hash, apiKey string) (*VTFileResponse, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("VirusTotal API key not provided")
	}
	raw, err := httpclient.DoGet(vtEndpointHash+hash, map[string]string{"x-apikey": apiKey})
	if err != nil {
		return nil, fmt.Errorf("VT hash: %w", err)
	}
	var r VTFileResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("VT hash parse: %w", err)
	}
	return &r, nil
}

// ── Mapping functions ─────────────────────────────────────────────────────────

// MapVTIPResult converts a VTIPResult (internal cache type) into the IPVirusTotal
// struct used in IP scan output. Called by the IP enrichment orchestrator.
func MapVTIPResult(r *VTIPResult) IPVirusTotal {
	return IPVirusTotal{
		Malicious:  r.Malicious,
		Suspicious: r.Suspicious,
		Undetected: r.Undetected,
		Harmless:   r.Harmless,
		Reputation: r.Reputation,
	}
}

// MapVTHashResult converts a raw VTFileResponse into a HashVirusTotal struct
// and also returns the count of malicious sandbox verdicts found.
// Called by the hash enrichment orchestrator.
func MapVTHashResult(r *VTFileResponse) (HashVirusTotal, int) {
	a := r.Data.Attributes
	out := HashVirusTotal{
		MD5:                  a.MD5,
		SHA1:                 a.SHA1,
		SHA256:               a.SHA256,
		MeaningfulName:       a.MeaningfulName,
		Magic:                a.Magic,
		Magika:               a.Magika,
		Malicious:            a.LastAnalysisStats.Malicious,
		Suspicious:           a.LastAnalysisStats.Suspicious,
		Harmless:             a.LastAnalysisStats.Harmless,
		Undetected:           a.LastAnalysisStats.Undetected,
		Reputation:           a.Reputation,
		SuggestedThreatLabel: a.PopularThreatClassification.SuggestedThreatLabel,
	}

	for _, c := range a.PopularThreatClassification.PopularThreatCategory {
		out.PopularThreatCategories = append(out.PopularThreatCategories, c.Value)
	}
	for _, n := range a.PopularThreatClassification.PopularThreatName {
		out.PopularThreatNames = append(out.PopularThreatNames, n.Value)
	}

	sandboxMal := 0
	seen := map[string]bool{}
	for _, sv := range a.SandboxVerdicts {
		if sv.Category == "malicious" {
			sandboxMal++
			for _, mc := range sv.MalwareClassification {
				if !seen[mc] {
					out.SandboxMalwareClassifications = append(out.SandboxMalwareClassifications, mc)
					seen[mc] = true
				}
			}
		}
	}

	if len(a.SigmaAnalysisSummary) > 0 {
		out.SigmaAnalysisSummary = make(map[string]SigmaSummaryEntry)
		for ruleset, stats := range a.SigmaAnalysisSummary {
			out.SigmaAnalysisSummary[ruleset] = SigmaSummaryEntry{
				Critical: stats.Critical,
				High:     stats.High,
				Medium:   stats.Medium,
				Low:      stats.Low,
			}
		}
	}

	out.SignatureSigners = a.SignatureInfo.Signers
	if len(a.SignatureInfo.SignersDetails) > 0 {
		d := a.SignatureInfo.SignersDetails[0]
		out.SignerDetail = &VTSignerDetail{
			CertIssuer: d.CertIssuer,
			Name:       d.Name,
			Status:     d.Status,
			ValidFrom:  d.ValidFrom,
			ValidTo:    d.ValidTo,
		}
	}

	return out, sandboxMal
}
