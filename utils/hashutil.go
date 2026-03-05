// utils/hashutil.go — Hash enrichment: VirusTotal + MalwareBazaar.
//
// Supports MD5 (32), SHA1 (40), SHA256 (64) hex strings.
// Sources:
//   - VirusTotal     GET  https://www.virustotal.com/api/v3/files/{hash}
//   - MalwareBazaar  POST https://mb-api.abuse.ch/api/v1/  (form data)
package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

const (
	endpointVTHash = "https://www.virustotal.com/api/v3/files/"
	endpointMBHash = "https://mb-api.abuse.ch/api/v1/"
)

// ── VirusTotal /files/{hash} ──────────────────────────────────────────────────

type vtFileAttr struct {
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

type vtFileResponse struct {
	Data struct {
		Attributes vtFileAttr `json:"attributes"`
	} `json:"data"`
}

// ── MalwareBazaar query_hash ──────────────────────────────────────────────────

type mbHashResp struct {
	QueryStatus string    `json:"query_status"`
	Data        []mbEntry `json:"data"`
}

type mbEntry struct {
	FileName  string   `json:"file_name"`
	FileType  string   `json:"file_type"`
	Signature string   `json:"signature"`
	Tags      []string `json:"tags"`
	Comment   string   `json:"comment"`
}

// ── HashResult — exactly the fields from the spec ─────────────────────────────

// VTSignerDetail holds info about a code-signing certificate.
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

// HashLinks holds direct URLs to third-party pages.
type HashLinks struct {
	VirusTotal    string `json:"virustotal"`
	MalwareBazaar string `json:"malwarebazaar"`
}

// HashResult is the lean merged output of a hash lookup.
type HashResult struct {
	Hash      string `json:"hash"`
	HashType  string `json:"hashType"`
	RiskLevel string `json:"riskLevel"`

	// VT — identity
	MD5            string `json:"md5,omitempty"`
	SHA1           string `json:"sha1,omitempty"`
	SHA256         string `json:"sha256,omitempty"`
	MeaningfulName string `json:"meaningfulName,omitempty"`
	Magic          string `json:"magic,omitempty"`
	Magika         string `json:"magika,omitempty"`

	// VT — detection stats
	VTHarmless   int `json:"vtHarmless"`
	VTMalicious  int `json:"vtMalicious"`
	VTSuspicious int `json:"vtSuspicious"`
	VTUndetected int `json:"vtUndetected"`
	VTReputation int `json:"vtReputation"`

	// VT — threat classification
	SuggestedThreatLabel    string   `json:"suggestedThreatLabel,omitempty"`
	PopularThreatCategories []string `json:"popularThreatCategories,omitempty"`
	PopularThreatNames      []string `json:"popularThreatNames,omitempty"`

	// VT — sandbox verdicts (malware_classification values from malicious sandboxes)
	SandboxMalwareClassifications []string `json:"sandboxMalwareClassifications,omitempty"`

	// VT — sigma analysis summary
	SigmaAnalysisSummary map[string]SigmaSummaryEntry `json:"sigmaAnalysisSummary,omitempty"`

	// VT — signature info
	SignatureSigners string          `json:"signatureSigners,omitempty"`
	SignerDetail     *VTSignerDetail `json:"signerDetail,omitempty"` // first signer only

	// MB fields
	MBQueryStatus string   `json:"mbQueryStatus"`
	MBFileName    string   `json:"mbFileName,omitempty"`
	MBFileType    string   `json:"mbFileType,omitempty"`
	MBSignature   string   `json:"mbSignature,omitempty"`
	MBTags        []string `json:"mbTags,omitempty"`
	MBComment     string   `json:"mbComment,omitempty"`

	Links HashLinks `json:"links"`
}

// ── helpers ───────────────────────────────────────────────────────────────────

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

// doPost sends an HTTP POST with application/x-www-form-urlencoded body.
func doPost(rawURL, body string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "iocscan/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, rawURL)
	}
	return io.ReadAll(resp.Body)
}

// ── cache ─────────────────────────────────────────────────────────────────────

var hashCacheTables = map[string]bool{
	"VT_HASH": true,
	"MB_HASH": true,
}

func getHashCached(hash, table string) string {
	if !hashCacheTables[table] {
		return ""
	}
	db, err := openDB()
	if err != nil {
		return ""
	}
	defer db.Close()
	var data, createdAt string
	q := fmt.Sprintf("SELECT DATA, CREATED_AT FROM %s WHERE IP = ?", table)
	if err := db.QueryRow(q, hash).Scan(&data, &createdAt); err != nil {
		return ""
	}
	t, err := parseSQLiteTime(createdAt)
	if err != nil || time.Since(t.UTC()) > cacheMaxAge {
		db.Exec(fmt.Sprintf("DELETE FROM %s WHERE IP = ?", table), hash)
		return ""
	}
	return data
}

func putHashCached(hash, data, table string) {
	if !hashCacheTables[table] {
		return
	}
	db, err := openDB()
	if err != nil {
		return
	}
	defer db.Close()
	q := fmt.Sprintf("INSERT OR REPLACE INTO %s (IP, DATA) VALUES (?, ?)", table)
	db.Exec(q, hash, data)
}

// ClearHashCaches deletes all rows from the specified hash cache tables.
// Returns the total number of rows deleted.
func ClearHashCaches(tables []string) int {
	db, err := openDB()
	if err != nil {
		return 0
	}
	defer db.Close()
	total := 0
	for _, t := range tables {
		if !hashCacheTables[t] {
			continue
		}
		res, err := db.Exec(fmt.Sprintf("DELETE FROM %s", t))
		if err == nil {
			n, _ := res.RowsAffected()
			total += int(n)
		}
	}
	return total
}

// ── API fetchers ──────────────────────────────────────────────────────────────

func fetchVTHash(hash, vtKey string) (*vtFileResponse, error) {
	if vtKey == "" {
		return nil, fmt.Errorf("VirusTotal API key not provided")
	}
	raw, err := doGet(endpointVTHash+hash, map[string]string{"x-apikey": vtKey})
	if err != nil {
		return nil, fmt.Errorf("VT hash: %w", err)
	}
	var r vtFileResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("VT hash parse: %w", err)
	}
	return &r, nil
}

// fetchMBHash queries MalwareBazaar using multipart/form-data POST (as per API spec).
// Returns the entry (or nil), the raw query_status string, and any transport error.
func fetchMBHash(hash, mbKey string) (*mbEntry, string, error) {
	if mbKey == "" {
		return nil, "no_api_key", nil
	}

	// Build multipart/form-data body — exactly as the MB API expects
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("query", "get_info")
	w.WriteField("hash", hash)
	w.Close()

	req, err := http.NewRequest(http.MethodPost, endpointMBHash, &buf)
	if err != nil {
		return nil, "error", err
	}
	// Auth-Key is a request header; Content-Type must include the multipart boundary
	req.Header.Set("Auth-Key", mbKey)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("User-Agent", "iocscan/1.0")
	req.Header.Set("Accept", "*/*")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "error", fmt.Errorf("MB hash request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "error", fmt.Errorf("MB hash read: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Sprintf("http_%d", resp.StatusCode), fmt.Errorf("MB HTTP %d: %s", resp.StatusCode, string(raw))
	}

	var mbResp mbHashResp
	if err := json.Unmarshal(raw, &mbResp); err != nil {
		return nil, "parse_error", fmt.Errorf("MB parse: %w — body: %.200s", err, string(raw))
	}

	// Pass through the exact query_status from MB — never mask it
	status := mbResp.QueryStatus
	if status == "" {
		status = "unknown_response"
	}

	if status != "ok" || len(mbResp.Data) == 0 {
		// Not found or an API error — return the real status so UI can show it
		return nil, status, nil
	}

	return &mbResp.Data[0], "ok", nil
}

// ── LookupHash ────────────────────────────────────────────────────────────────

// LookupHash enriches a hash using VirusTotal + MalwareBazaar concurrently.
func LookupHash(hash, vtKey, mbKey string, useCache bool) (string, error) {
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
	}

	// ── concurrent fetches ────────────────────────────────────────────────────
	type vtRes struct {
		d   *vtFileResponse
		err error
	}
	type mbRes struct {
		d      *mbEntry
		status string
		err    error
	}
	vtCh := make(chan vtRes, 1)
	mbCh := make(chan mbRes, 1)

	go func() {
		if useCache {
			if raw := getHashCached(hash, "VT_HASH"); raw != "" {
				var r vtFileResponse
				json.Unmarshal([]byte(raw), &r)
				vtCh <- vtRes{d: &r}
				return
			}
		}
		r, err := fetchVTHash(hash, vtKey)
		if err == nil && r != nil && useCache {
			b, _ := json.Marshal(r)
			putHashCached(hash, string(b), "VT_HASH")
		}
		vtCh <- vtRes{d: r, err: err}
	}()

	go func() {
		if useCache {
			if raw := getHashCached(hash, "MB_HASH"); raw != "" {
				var e mbEntry
				json.Unmarshal([]byte(raw), &e)
				mbCh <- mbRes{d: &e, status: "ok"}
				return
			}
		}
		e, status, err := fetchMBHash(hash, mbKey)
		if err == nil && e != nil && useCache {
			b, _ := json.Marshal(e)
			putHashCached(hash, string(b), "MB_HASH")
		}
		mbCh <- mbRes{d: e, status: status, err: err}
	}()

	vr := <-vtCh
	mr := <-mbCh

	// ── populate VT fields ────────────────────────────────────────────────────
	sandboxMal := 0
	if vr.d != nil {
		a := vr.d.Data.Attributes

		result.MD5 = a.MD5
		result.SHA1 = a.SHA1
		result.SHA256 = a.SHA256
		result.MeaningfulName = a.MeaningfulName
		result.Magic = a.Magic
		result.Magika = a.Magika

		result.VTHarmless = a.LastAnalysisStats.Harmless
		result.VTMalicious = a.LastAnalysisStats.Malicious
		result.VTSuspicious = a.LastAnalysisStats.Suspicious
		result.VTUndetected = a.LastAnalysisStats.Undetected
		result.VTReputation = a.Reputation

		result.SuggestedThreatLabel = a.PopularThreatClassification.SuggestedThreatLabel
		for _, c := range a.PopularThreatClassification.PopularThreatCategory {
			result.PopularThreatCategories = append(result.PopularThreatCategories, c.Value)
		}
		for _, n := range a.PopularThreatClassification.PopularThreatName {
			result.PopularThreatNames = append(result.PopularThreatNames, n.Value)
		}

		// Collect malware_classification from malicious sandbox verdicts
		seen := map[string]bool{}
		for _, sv := range a.SandboxVerdicts {
			if sv.Category == "malicious" {
				sandboxMal++
				for _, mc := range sv.MalwareClassification {
					if !seen[mc] {
						result.SandboxMalwareClassifications = append(result.SandboxMalwareClassifications, mc)
						seen[mc] = true
					}
				}
			}
		}

		// Sigma summary
		if len(a.SigmaAnalysisSummary) > 0 {
			result.SigmaAnalysisSummary = make(map[string]SigmaSummaryEntry)
			for ruleset, stats := range a.SigmaAnalysisSummary {
				result.SigmaAnalysisSummary[ruleset] = SigmaSummaryEntry{
					Critical: stats.Critical,
					High:     stats.High,
					Medium:   stats.Medium,
					Low:      stats.Low,
				}
			}
		}

		// Signature info
		result.SignatureSigners = a.SignatureInfo.Signers
		if len(a.SignatureInfo.SignersDetails) > 0 {
			d := a.SignatureInfo.SignersDetails[0]
			result.SignerDetail = &VTSignerDetail{
				CertIssuer: d.CertIssuer,
				Name:       d.Name,
				Status:     d.Status,
				ValidFrom:  d.ValidFrom,
				ValidTo:    d.ValidTo,
			}
		}

		// Upgrade links to canonical SHA256
		if a.SHA256 != "" {
			result.Links.VirusTotal = "https://www.virustotal.com/gui/file/" + a.SHA256
			result.Links.MalwareBazaar = "https://bazaar.abuse.ch/sample/" + a.SHA256
		}
	}

	// ── populate MB fields ────────────────────────────────────────────────────
	result.MBQueryStatus = mr.status
	if mr.d != nil {
		e := mr.d
		result.MBFileName = e.FileName
		result.MBFileType = e.FileType
		result.MBSignature = e.Signature
		result.MBTags = e.Tags
		result.MBComment = e.Comment
	}

	result.RiskLevel = assessHashRisk(result.VTMalicious, mr.status == "ok" && mr.d != nil, sandboxMal)

	j, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(j), nil
}
