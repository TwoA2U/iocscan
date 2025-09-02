package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// Utility struct
type IPProcessor struct {
	APIVT        string
	APIAbuseIPDB string
	APIipapiis   string
}

var (
	vt      = "www.virustotal.com/api/v3/ip_addresses/"
	abuse   = "api.abuseipdb.com/api/v2/check"
	ipapiis = "api.ipapi.is"
)

type APIipapiout struct {
	Ip          string `json:"ip"`
	CompanyName string `json:"company_name"`
	CompanyType string `json:"company_type"`
	ASNOrg      string `json:"asn_org"`
	Country     string `json:"country"`
	State       string `json:"state"`
	City        string `json:"city"`
	Timezone    string `json:"timezone"`
}

type APIipapiResponse struct {
	Ip      string `json:"ip"`
	Company struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"company"`
	ASN struct {
		Org string `json:"org"`
	} `json:"asn"`
	Location struct {
		Country  string `json:"country"`
		State    string `json:"state"`
		City     string `json:"city"`
		Timezone string `json:"timezone"`
	} `json:"location"`
}

type APIAbuseResponse struct {
	Data struct {
		IPaddress            string   `json:"ipAddress"`
		Ispublic             bool     `json:"isPublic"`
		Iswhitelisted        bool     `json:"isWhitelisted"`
		AbuseConfidenceScore int      `json:"abuseConfidenceScore"`
		Countrycode          string   `json:"countryCode"`
		Isp                  string   `json:"isp"`
		Hostnames            []string `json:"hostnames"`
		TotalReports         int      `json:"totalReports"`
	} `json:"data"`
}

type APIAbuseout struct {
	IPaddress            string   `json:"ipAddress"`
	Ispublic             bool     `json:"isPublic"`
	Iswhitelisted        bool     `json:"isWhitelisted"`
	AbuseConfidenceScore int      `json:"abuseConfidenceScore"`
	Countrycode          string   `json:"countryCode"`
	Isp                  string   `json:"isp"`
	Hostnames            []string `json:"hostnames"`
	TotalReports         int      `json:"totalReports"`
}

type APIVTResponse struct {
	Data struct {
		IPaddress  string `json:"id"`
		Attributes struct {
			Last_analysis_stats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Harmless   int `json:"harmless"`
			} `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
}

type APIVTout struct {
	IPaddress  string `json:"id"`
	Malicious  int    `json:"malicious"`
	Suspicious int    `json:"suspicious"`
	Undetected int    `json:"undetected"`
	Harmless   int    `json:"harmless"`
}

type Complexcheck struct {
	IPaddress            string   `json:"ipAddress"`
	Hostnames            []string `json:"hostnames"`
	Isp                  string   `json:"isp"`
	Ispublic             bool     `json:"isPublic"`
	Iswhitelisted        bool     `json:"isWhitelisted"`
	Countrycode          string   `json:"countryCode"`
	VTStats_S_U_H        string   `json:"vtStats_S_U_H"`
	TotalReports         int      `json:"totalReports"`
	AbuseConfidenceScore int      `json:"abuseConfidenceScore"`
	VTmalicious          int      `json:"vtMalicious"`
}

func Split(r rune) bool {
	return r == '\r' || r == '\n' || r == ',' || r == ' ' || r == '\t'
}

func CheckIP(ipaddr string) ([]string, error) {
	processedIp := strings.FieldsFunc(ipaddr, Split)
	for i := 0; i < len(processedIp); i++ {
		ip, status := netip.ParseAddr(strings.TrimSpace(processedIp[i]))
		if status != nil {
			return nil, status
		}
		processedIp[i] = ip.String()
	}
	return processedIp, nil
}

// Constructor
func NewIPProcessor(VT string, ABuseIPDB string, ipapiis string) *IPProcessor {
	return &IPProcessor{APIVT: VT, APIAbuseIPDB: ABuseIPDB, APIipapiis: ipapiis}
}

func (p *IPProcessor) Lookup(ipaddr string, mode string) (string, error) {
	if strings.ToLower(mode) == "simple" {
		// do request to ipapi only
		return sendipapi(ipaddr, p.APIipapiis)

	}
	return complex(ipaddr, p.APIAbuseIPDB, p.APIVT)
}

func complex(ipaddr string, keyAbuse string, apiVT string) (string, error) {
	abusejson, err := sendAbuse(ipaddr, keyAbuse)
	if err != nil {
		return "", err
	}
	vtjson, err := sendVT(ipaddr, apiVT)
	if err != nil {
		return "", err
	}
	slim := Complexcheck{
		IPaddress:            abusejson.IPaddress,
		Hostnames:            abusejson.Hostnames,
		Isp:                  abusejson.Isp,
		Ispublic:             abusejson.Ispublic,
		Iswhitelisted:        abusejson.Iswhitelisted,
		Countrycode:          abusejson.Countrycode,
		VTStats_S_U_H:        fmt.Sprintf("%d/%d/%d", vtjson.Suspicious, vtjson.Undetected, vtjson.Harmless),
		TotalReports:         abusejson.TotalReports,
		AbuseConfidenceScore: abusejson.AbuseConfidenceScore,
		VTmalicious:          vtjson.Malicious,
	}
	// Convert to JSON string
	out, err := json.MarshalIndent(slim, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out) + ",", nil
}

func sendVT(ip string, key string) (*APIVTout, error) {

	data := GetValuetDB(ip, "VT_IP")
	if data != "" {
		var VTdata APIVTout
		if err := json.Unmarshal([]byte(data), &VTdata); err != nil {
			return nil, err
		}
		return &VTdata, nil
	}

	url := fmt.Sprintf("https://%s%s", vt, ip)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", key)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	// Parse API response
	var apiResp APIVTResponse
	if err := json.NewDecoder(res.Body).Decode(&apiResp); err != nil {
		return nil, err
	}
	// Map into slim output
	slim := APIVTout{
		IPaddress:  apiResp.Data.IPaddress,
		Malicious:  apiResp.Data.Attributes.Last_analysis_stats.Malicious,
		Suspicious: apiResp.Data.Attributes.Last_analysis_stats.Suspicious,
		Undetected: apiResp.Data.Attributes.Last_analysis_stats.Undetected,
		Harmless:   apiResp.Data.Attributes.Last_analysis_stats.Harmless,
	}
	out, err := json.MarshalIndent(slim, "", "  ")
	if err != nil {
		return nil, err
	}

	InsertValueDB(ip, string(out), "VT_IP")

	return &slim, nil
}

func sendAbuse(ip string, key string) (*APIAbuseout, error) {

	data := GetValuetDB(ip, "Abuse_IP")
	if data != "" {
		var Abusedata APIAbuseout
		if err := json.Unmarshal([]byte(data), &Abusedata); err != nil {
			return nil, err
		}

		return &Abusedata, nil
	}

	base := fmt.Sprintf("https://%s", abuse)
	u, _ := url.Parse(base)
	q := u.Query()
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", "90")
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Key", key)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	// Parse API response
	var apiResp APIAbuseResponse
	if err := json.NewDecoder(res.Body).Decode(&apiResp); err != nil {
		return nil, err
	}

	// Map into slim output
	slim := APIAbuseout{
		IPaddress:            apiResp.Data.IPaddress,
		Hostnames:            apiResp.Data.Hostnames,
		Ispublic:             apiResp.Data.Ispublic,
		Iswhitelisted:        apiResp.Data.Iswhitelisted,
		AbuseConfidenceScore: apiResp.Data.AbuseConfidenceScore,
		Countrycode:          apiResp.Data.Countrycode,
		Isp:                  apiResp.Data.Isp,
		TotalReports:         apiResp.Data.TotalReports,
	}

	out, err := json.MarshalIndent(slim, "", "  ")
	if err != nil {
		return nil, err
	}

	InsertValueDB(ip, string(out), "ABUSE_IP")
	return &slim, nil
}

func sendipapi(ip string, key string) (string, error) {

	data := GetValuetDB(ip, "IPAPIIS_IP")
	if data != "" {
		return data, nil
	}

	payload := map[string]string{
		"q":   ip,
		"key": key,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	// Make POST request (http.Post is shorter than manually building client/req)
	url := fmt.Sprintf("https://%s", ipapiis)

	res, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	// Parse API response
	var apiResp APIipapiResponse
	if err := json.NewDecoder(res.Body).Decode(&apiResp); err != nil {
		return "", err
	}
	// Map into slim output
	slim := APIipapiout{
		Ip:          apiResp.Ip,
		CompanyName: apiResp.Company.Name,
		CompanyType: apiResp.Company.Type,
		ASNOrg:      apiResp.ASN.Org,
		Country:     apiResp.Location.Country,
		State:       apiResp.Location.State,
		City:        apiResp.Location.City,
		Timezone:    apiResp.Location.Timezone,
	}

	// Convert to JSON string
	out, err := json.MarshalIndent(slim, "", "  ")
	if err != nil {
		return "", err
	}

	InsertValueDB(ip, string(out), "IPAPIIS_IP")
	return string(out) + ",", nil
}
