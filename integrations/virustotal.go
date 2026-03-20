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
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/TwoA2U/iocscan/internal/httpclient"
)

const (
	vtEndpointIP     = "https://www.virustotal.com/api/v3/ip_addresses/"
	vtEndpointHash   = "https://www.virustotal.com/api/v3/files/"
	vtEndpointDomain = "https://www.virustotal.com/api/v3/domains/"
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
			Reputation       int   `json:"reputation"`
			LastAnalysisDate int64 `json:"last_analysis_date"`
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

	LastAnalysisDate int64 `json:"last_analysis_date"`

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
	IPAddress        string `json:"ipAddress"`
	Malicious        int    `json:"malicious"`
	Suspicious       int    `json:"suspicious"`
	Undetected       int    `json:"undetected"`
	Harmless         int    `json:"harmless"`
	Reputation       int    `json:"reputation"`
	LastAnalysisDate string `json:"lastAnalysisDate,omitempty"`
}

// IPVirusTotal holds the VirusTotal enrichment fields surfaced in an IP scan result.
// Error is non-empty when the vendor call failed; other fields will be zero values.
// This allows the orchestrator to return partial results instead of aborting the
// entire scan when VirusTotal is unavailable (e.g. missing API key, rate limit).
type IPVirusTotal struct {
	Malicious        int    `json:"malicious"`
	Suspicious       int    `json:"suspicious"`
	Undetected       int    `json:"undetected"`
	Harmless         int    `json:"harmless"`
	Reputation       int    `json:"reputation"`
	LastAnalysisDate string `json:"lastAnalysisDate,omitempty"`
	Error            string `json:"error,omitempty"`
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
	Malicious        int    `json:"malicious"`
	Suspicious       int    `json:"suspicious"`
	Harmless         int    `json:"harmless"`
	Undetected       int    `json:"undetected"`
	Reputation       int    `json:"reputation"`
	LastAnalysisDate string `json:"lastAnalysisDate,omitempty"`

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

// epochToDate converts a Unix timestamp to a readable UTC date string.
func epochToDate(epoch int64) string {
	if epoch == 0 {
		return ""
	}
	return time.Unix(epoch, 0).UTC().Format("2006-01-02 15:04 UTC")
}

// FetchVTIP queries VirusTotal for an IP address.
// ctx is honoured for cancellation — a browser disconnect aborts the call.
func FetchVTIP(ctx context.Context, ip, apiKey string) (*VTIPResult, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("VirusTotal API key not provided")
	}
	body, err := httpclient.DoGetCtx(ctx, vtEndpointIP+ip, map[string]string{"x-apikey": apiKey})
	if err != nil {
		return nil, fmt.Errorf("VT IP: %w", err)
	}

	var resp VTIPResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("VT IP parse: %w", err)
	}

	return &VTIPResult{
		IPAddress:        resp.Data.ID,
		Malicious:        resp.Data.Attributes.LastAnalysisStats.Malicious,
		Suspicious:       resp.Data.Attributes.LastAnalysisStats.Suspicious,
		Undetected:       resp.Data.Attributes.LastAnalysisStats.Undetected,
		Harmless:         resp.Data.Attributes.LastAnalysisStats.Harmless,
		Reputation:       resp.Data.Attributes.Reputation,
		LastAnalysisDate: epochToDate(resp.Data.Attributes.LastAnalysisDate),
	}, nil
}

// FetchVTHash queries VirusTotal for a file hash (MD5, SHA1, or SHA256).
// ctx is honoured for cancellation.
func FetchVTHash(ctx context.Context, hash, apiKey string) (*VTFileResponse, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("VirusTotal API key not provided")
	}
	raw, err := httpclient.DoGetCtx(ctx, vtEndpointHash+hash, map[string]string{"x-apikey": apiKey})
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
		Malicious:        r.Malicious,
		Suspicious:       r.Suspicious,
		Undetected:       r.Undetected,
		Harmless:         r.Harmless,
		Reputation:       r.Reputation,
		LastAnalysisDate: r.LastAnalysisDate,
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
		LastAnalysisDate:     epochToDate(a.LastAnalysisDate),
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

// ── Integration interface implementations ─────────────────────────────────────
//
// VirusTotalIP and VirusTotalHash wrap the existing FetchVTIP / FetchVTHash
// functions to satisfy the Integration interface. All existing logic above
// is unchanged; these structs are purely additive.

// VirusTotalIP handles VT enrichment for IP address indicators.
type VirusTotalIP struct{}

func (v VirusTotalIP) Manifest() Manifest {
	return Manifest{
		Name:     "virustotal_ip",
		Label:    "VirusTotal",
		Icon:     "🦠",
		Enabled:  true,
		IOCTypes: []IOCType{IOCTypeIP},
		Auth: AuthConfig{
			KeyRef:   "vt",
			Label:    "VirusTotal",
			Optional: false,
		},
		Cache: CacheConfig{
			Table:    "VT_IP",
			TTLHours: 24,
		},
		RiskRules: []RiskRule{
			{
				Field: "malicious",
				Type:  RiskThreshold,
				Thresholds: []RiskThresholdRule{
					{Gte: 5, Level: "CRITICAL"},
					{Gte: 2, Level: "HIGH"},
					{Gte: 1, Level: "MEDIUM"},
				},
			},
		},
		Card: CardDef{
			Title:        "🦠 VirusTotal",
			Order:        1,
			LinkTemplate: "https://www.virustotal.com/gui/ip-address/{ioc}",
			LinkLabel:    "↗ VT",
			Fields: []FieldDef{
				{
					Key:   "malicious",
					Label: "Malicious",
					Type:  FieldTypeNumber,
				},
				{
					Key:   "suspicious",
					Label: "Suspicious",
					Type:  FieldTypeNumber,
				},
				{
					Key:   "harmless",
					Label: "Harmless",
					Type:  FieldTypeNumber,
				},
				{
					Key:   "undetected",
					Label: "Undetected",
					Type:  FieldTypeNumber,
				},
				{
					Key:   "reputation",
					Label: "Reputation",
					Type:  FieldTypeNumber,
				},
			},
		},
		TableColumns: []TableColumn{
			{Key: "malicious", Label: "VT Malicious", DefaultVisible: true},
			{Key: "suspicious", Label: "VT Suspicious", DefaultVisible: true},
			{Key: "harmless", Label: "VT Harmless", DefaultVisible: false},
			{Key: "reputation", Label: "VT Reputation", DefaultVisible: false},
		},
	}
}

func (v VirusTotalIP) Run(ctx context.Context, ioc, apiKey string, useCache bool) (*Result, error) {
	if useCache {
		if raw := cachedGet(ioc, "VT_IP"); raw != "" {
			var r VTIPResult
			if err := json.Unmarshal([]byte(raw), &r); err == nil {
				return vtIPToResult(&r), nil
			}
		}
	}

	r, err := FetchVTIP(ctx, ioc, apiKey)
	if err != nil {
		return &Result{Error: err.Error()}, nil
	}

	if b, e := json.Marshal(r); e == nil {
		cachedPut(ioc, string(b), "VT_IP")
	}
	return vtIPToResult(r), nil
}

func vtIPToResult(r *VTIPResult) *Result {
	return &Result{Fields: map[string]any{
		"malicious":        r.Malicious,
		"suspicious":       r.Suspicious,
		"undetected":       r.Undetected,
		"harmless":         r.Harmless,
		"reputation":       r.Reputation,
		"lastAnalysisDate": r.LastAnalysisDate,
	}}
}

// ── VirusTotalHash ────────────────────────────────────────────────────────────

// VirusTotalHash handles VT enrichment for file hash indicators.
type VirusTotalHash struct{}

func (v VirusTotalHash) Manifest() Manifest {
	return Manifest{
		Name:     "virustotal_hash",
		Label:    "VirusTotal",
		Icon:     "🦠",
		Enabled:  true,
		IOCTypes: []IOCType{IOCTypeHash},
		Auth: AuthConfig{
			KeyRef:   "vt",
			Label:    "VirusTotal",
			Optional: false,
		},
		Cache: CacheConfig{
			Table:    "VT_HASH",
			TTLHours: 24,
		},
		RiskRules: []RiskRule{
			{
				Field: "malicious",
				Type:  RiskThreshold,
				Thresholds: []RiskThresholdRule{
					{Gte: 15, Level: "CRITICAL"},
					{Gte: 5, Level: "HIGH"},
					{Gte: 1, Level: "MEDIUM"},
				},
			},
		},
		Card: CardDef{
			Title:        "🦠 VirusTotal",
			Order:        1,
			LinkTemplate: "https://www.virustotal.com/gui/file/{ioc}",
			LinkLabel:    "↗ VT",
			Fields: []FieldDef{
				{Key: "malicious", Label: "Malicious", Type: FieldTypeNumber},
				{Key: "suspicious", Label: "Suspicious", Type: FieldTypeNumber},
				{Key: "harmless", Label: "Harmless", Type: FieldTypeNumber},
				{Key: "undetected", Label: "Undetected", Type: FieldTypeNumber},
				{Key: "reputation", Label: "Reputation", Type: FieldTypeNumber},
				{Key: "meaningfulName", Label: "File Name", Type: FieldTypeString},
				{Key: "magic", Label: "Magic", Type: FieldTypeString},
				{Key: "magika", Label: "Magika", Type: FieldTypeString},
				{Key: "suggestedThreatLabel", Label: "Threat Label", Type: FieldTypeString},
				{Key: "popularThreatNames", Label: "Threat Names", Type: FieldTypeTags},
				{Key: "sandboxMalwareClassifications", Label: "Sandbox Verdicts", Type: FieldTypeTags},
				{Key: "signatureSigners", Label: "Signer", Type: FieldTypeString},
				{Key: "md5", Label: "MD5", Type: FieldTypeString},
				{Key: "sha1", Label: "SHA1", Type: FieldTypeString},
				{Key: "sha256", Label: "SHA256", Type: FieldTypeString},
			},
		},
		TableColumns: []TableColumn{
			{Key: "malicious", Label: "VT Malicious", DefaultVisible: true},
			{Key: "suspicious", Label: "VT Suspicious", DefaultVisible: true},
			{Key: "suggestedThreatLabel", Label: "Threat Label", DefaultVisible: true},
			{Key: "meaningfulName", Label: "File Name", DefaultVisible: true},
			{Key: "magika", Label: "File Type", DefaultVisible: true},
			{Key: "signatureSigners", Label: "Signer", DefaultVisible: false},
			{Key: "sha256", Label: "SHA256", DefaultVisible: false},
		},
	}
}

func (v VirusTotalHash) Run(ctx context.Context, ioc, apiKey string, useCache bool) (*Result, error) {
	if useCache {
		if raw := cachedGet(ioc, "VT_HASH"); raw != "" {
			var r VTFileResponse
			if err := json.Unmarshal([]byte(raw), &r); err == nil {
				mapped, _ := MapVTHashResult(&r)
				return vtHashToResult(mapped), nil
			}
		}
	}

	r, err := FetchVTHash(ctx, ioc, apiKey)
	if err != nil {
		return &Result{Error: err.Error()}, nil
	}

	if b, e := json.Marshal(r); e == nil {
		cachedPut(ioc, string(b), "VT_HASH")
	}
	mapped, _ := MapVTHashResult(r)
	return vtHashToResult(mapped), nil
}

func vtHashToResult(h HashVirusTotal) *Result {
	fields := map[string]any{
		"malicious":                     h.Malicious,
		"suspicious":                    h.Suspicious,
		"harmless":                      h.Harmless,
		"undetected":                    h.Undetected,
		"reputation":                    h.Reputation,
		"lastAnalysisDate":              h.LastAnalysisDate,
		"meaningfulName":                h.MeaningfulName,
		"magic":                         h.Magic,
		"magika":                        h.Magika,
		"suggestedThreatLabel":          h.SuggestedThreatLabel,
		"popularThreatNames":            h.PopularThreatNames,
		"popularThreatCategories":       h.PopularThreatCategories,
		"sandboxMalwareClassifications": h.SandboxMalwareClassifications,
		"signatureSigners":              h.SignatureSigners,
		"md5":                           h.MD5,
		"sha1":                          h.SHA1,
		"sha256":                        h.SHA256,
	}
	if h.SignerDetail != nil {
		fields["signerStatus"] = h.SignerDetail.Status
		fields["signerName"] = h.SignerDetail.Name
		fields["signerCertIssuer"] = h.SignerDetail.CertIssuer
		fields["signerValidFrom"] = h.SignerDetail.ValidFrom
		fields["signerValidTo"] = h.SignerDetail.ValidTo
	}
	return &Result{Fields: fields}
}

// ── Domain types ──────────────────────────────────────────────────────────────

// VTDomainAttr holds the attributes block from a VT domain response.
// Detection stats mirror VTFileAttr; additional domain-specific fields added.
type VTDomainAttr struct {
	LastAnalysisStats struct {
		Harmless   int `json:"harmless"`
		Malicious  int `json:"malicious"`
		Suspicious int `json:"suspicious"`
		Undetected int `json:"undetected"`
	} `json:"last_analysis_stats"`
	Reputation                  int               `json:"reputation"`
	Categories                  map[string]string `json:"categories"`
	Registrar                   string            `json:"registrar"`
	CreationDate                int64             `json:"creation_date"`
	PopularThreatClassification struct {
		SuggestedThreatLabel string `json:"suggested_threat_label"`
	} `json:"popular_threat_classification"`
}

// VTDomainResponse is the raw API response for a domain lookup.
type VTDomainResponse struct {
	Data struct {
		Attributes VTDomainAttr `json:"attributes"`
	} `json:"data"`
}

// HashDomainVirusTotal holds the VT enrichment for a domain result.
type HashDomainVirusTotal struct {
	Malicious            int               `json:"malicious"`
	Suspicious           int               `json:"suspicious"`
	Harmless             int               `json:"harmless"`
	Undetected           int               `json:"undetected"`
	Reputation           int               `json:"reputation"`
	SuggestedThreatLabel string            `json:"suggestedThreatLabel,omitempty"`
	Categories           map[string]string `json:"categories,omitempty"`
	Registrar            string            `json:"registrar,omitempty"`
	CreationDate         string            `json:"creationDate,omitempty"`
	Error                string            `json:"error,omitempty"`
}

// ── Domain fetch ──────────────────────────────────────────────────────────────

// FetchVTDomain queries VirusTotal for a domain name.
func FetchVTDomain(ctx context.Context, domain, apiKey string) (*VTDomainResponse, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("VirusTotal API key not provided")
	}
	raw, err := httpclient.DoGetCtx(ctx, vtEndpointDomain+domain,
		map[string]string{"x-apikey": apiKey})
	if err != nil {
		return nil, fmt.Errorf("VT domain: %w", err)
	}
	var r VTDomainResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("VT domain parse: %w", err)
	}
	return &r, nil
}

// ── Domain integration wrapper ────────────────────────────────────────────────

// VirusTotalDomain implements Integration for domain IOC types.
type VirusTotalDomain struct{}

func (v VirusTotalDomain) Manifest() Manifest {
	return Manifest{
		Name:     "virustotal_domain",
		Label:    "VirusTotal",
		Icon:     "🧪",
		Enabled:  true,
		IOCTypes: []IOCType{IOCTypeDomain},
		Auth: AuthConfig{
			KeyRef:   "vt",
			Label:    "VirusTotal",
			Optional: false,
		},
		Cache: CacheConfig{
			Table:    "VT_DOMAIN",
			TTLHours: 24,
		},
		RiskRules: []RiskRule{
			{
				Field: "malicious",
				Type:  RiskThreshold,
				Thresholds: []RiskThresholdRule{
					{Gte: 5, Level: "CRITICAL"},
					{Gte: 2, Level: "HIGH"},
					{Gte: 1, Level: "MEDIUM"},
				},
			},
		},
		Card: CardDef{
			Title:        "🧪 VirusTotal",
			Order:        1,
			LinkTemplate: "https://www.virustotal.com/gui/domain/{ioc}",
			LinkLabel:    "↗ VirusTotal",
			Fields: []FieldDef{
				{Key: "malicious", Label: "Malicious", Type: FieldTypeNumber},
				{Key: "suspicious", Label: "Suspicious", Type: FieldTypeNumber},
				{Key: "harmless", Label: "Harmless", Type: FieldTypeNumber},
				{Key: "undetected", Label: "Undetected", Type: FieldTypeNumber},
				{Key: "reputation", Label: "Reputation", Type: FieldTypeNumber},
				{Key: "suggestedThreatLabel", Label: "Threat Label", Type: FieldTypeString},
				{Key: "registrar", Label: "Registrar", Type: FieldTypeString},
				{Key: "creationDate", Label: "Created", Type: FieldTypeString},
			},
		},
		TableColumns: []TableColumn{
			{Key: "malicious", Label: "VT Malicious", DefaultVisible: true},
			{Key: "suggestedThreatLabel", Label: "VT Threat", DefaultVisible: true},
			{Key: "registrar", Label: "Registrar", DefaultVisible: false},
		},
	}
}

func (v VirusTotalDomain) Run(ctx context.Context, ioc, apiKey string, useCache bool) (*Result, error) {
	if useCache {
		if raw := cachedGet(ioc, "VT_DOMAIN"); raw != "" {
			var r VTDomainResponse
			if err := json.Unmarshal([]byte(raw), &r); err == nil {
				return vtDomainToResult(&r), nil
			}
		}
	}
	r, err := FetchVTDomain(ctx, ioc, apiKey)
	if err != nil {
		return &Result{Error: err.Error()}, nil
	}
	if b, e := json.Marshal(r); e == nil {
		cachedPut(ioc, string(b), "VT_DOMAIN")
	}
	return vtDomainToResult(r), nil
}

func vtDomainToResult(r *VTDomainResponse) *Result {
	a := r.Data.Attributes
	var created string
	if a.CreationDate > 0 {
		created = time.Unix(a.CreationDate, 0).UTC().Format("2006-01-02 15:04:05")
	}
	return &Result{Fields: map[string]any{
		"malicious":            a.LastAnalysisStats.Malicious,
		"suspicious":           a.LastAnalysisStats.Suspicious,
		"harmless":             a.LastAnalysisStats.Harmless,
		"undetected":           a.LastAnalysisStats.Undetected,
		"reputation":           a.Reputation,
		"suggestedThreatLabel": a.PopularThreatClassification.SuggestedThreatLabel,
		"categories":           a.Categories,
		"registrar":            a.Registrar,
		"creationDate":         created,
	}}
}
