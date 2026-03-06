// integrations/virustotal.go — VirusTotal enrichment for IP addresses and file hashes.
//
// API docs: https://developers.virustotal.com/reference/overview
//
// IP lookup:   GET https://www.virustotal.com/api/v3/ip_addresses/{ip}
// Hash lookup: GET https://www.virustotal.com/api/v3/files/{hash}
//
// Auth: x-apikey header (required).
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

// ── IP lookup ─────────────────────────────────────────────────────────────────

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

// VTIPResult holds the cleaned VT enrichment for an IP address.
type VTIPResult struct {
	IPAddress  string `json:"ipAddress"`
	Malicious  int    `json:"malicious"`
	Suspicious int    `json:"suspicious"`
	Undetected int    `json:"undetected"`
	Harmless   int    `json:"harmless"`
	Reputation int    `json:"reputation"`
}

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

// ── Hash lookup ───────────────────────────────────────────────────────────────

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
