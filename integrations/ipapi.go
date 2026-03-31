// integrations/ipapi.go — ipapi.is geo and ASN enrichment for IP addresses.
//
// API docs: https://ipapi.is/
//
// Endpoint: GET https://api.ipapi.is/?q={ip}[&key={apiKey}]
// Auth: optional key query parameter (free tier works without one).
package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/TwoA2U/iocscan/internal/httpclient"
)

const ipapiEndpoint = "https://api.ipapi.is"

// IPAPIResponse is the raw response from ipapi.is.
type IPAPIResponse struct {
	IP      string `json:"ip"`
	RIR     string `json:"rir"`
	IsBogon bool   `json:"is_bogon"`
	IsMobile bool  `json:"is_mobile"`
	IsSatellite bool `json:"is_satellite"`
	IsCrawler bool `json:"is_crawler"`
	IsDatacenter bool `json:"is_datacenter"`
	IsTor bool `json:"is_tor"`
	IsProxy bool `json:"is_proxy"`
	IsVPN bool `json:"is_vpn"`
	IsAbuser bool `json:"is_abuser"`
	VPN struct {
		Service     string `json:"service"`
		Type        string `json:"type"`
		LastSeenStr string `json:"last_seen_str"`
	} `json:"vpn"`
	Company struct {
		Name        string `json:"name"`
		Type        string `json:"type"`
		AbuserScore string `json:"abuser_score"`
		Domain      string `json:"domain"`
		Network     string `json:"network"`
		Whois       string `json:"whois"`
	} `json:"company"`
	ASN struct {
		Org string `json:"org"`
	} `json:"asn"`
	Location struct {
		Country    string `json:"country"`
		CountryCode string `json:"country_code"`
		State      string `json:"state"`
		City       string `json:"city"`
		Timezone   string `json:"timezone"`
		LocalTime  string `json:"local_time"`
		IsDST      bool   `json:"is_dst"`
	} `json:"location"`
}

// FetchIPAPI queries ipapi.is for geo and ASN data about an IP address.
// apiKey is optional — leave empty to use the free public tier.
// ctx is honoured for cancellation.
func FetchIPAPI(ctx context.Context, ip, apiKey string) (*IPAPIResponse, error) {
	reqURL := fmt.Sprintf("%s/?q=%s", ipapiEndpoint, url.QueryEscape(ip))
	if apiKey != "" {
		reqURL += "&key=" + url.QueryEscape(apiKey)
	}

	body, err := httpclient.DoGetCtx(ctx, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("ipapi.is: %w", err)
	}

	var resp IPAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("ipapi.is parse: %w", err)
	}
	return &resp, nil
}

// ── Integration interface implementation ──────────────────────────────────────
//
// IPAPIIntegration wraps FetchIPAPI to satisfy the Integration interface.
// ipapi.is is optional (free tier, no key required).
// This also surfaces company.type (VPN/datacenter/hosting/isp) which was
// previously fetched but silently discarded by the old orchestrator.

type IPAPIIntegration struct{}

func (i IPAPIIntegration) Manifest() Manifest {
	return Manifest{
		Name:     "ipapi",
		Label:    "ipapi.is",
		Icon:     "🌍",
		Enabled:  true,
		IOCTypes: []IOCType{IOCTypeIP},
		Auth: AuthConfig{
			KeyRef:   "ipapi",
			Label:    "ipapi.is",
			Optional: true,
		},
		Cache: CacheConfig{
			Table:    "IPAPIIS_IP",
			TTLHours: 48,
		},
		// ipapi.is does not contribute directly to risk scoring;
		// it provides geo/ASN context used by the card and table.
		RiskRules: nil,
		Card: CardDef{
			Title:        "🌍 ipapi.is",
			Order:        3,
			LinkTemplate: "https://ipapi.is/?q={ioc}",
			LinkLabel:    "↗ ipapi.is",
			Fields: []FieldDef{
				{Key: "country", Label: "Country", Type: FieldTypeString},
				{Key: "city", Label: "City", Type: FieldTypeString},
				{Key: "state", Label: "State", Type: FieldTypeString},
				{Key: "timezone", Label: "Timezone", Type: FieldTypeString},
				{Key: "localTime", Label: "Local Time", Type: FieldTypeString},
				{Key: "org", Label: "Organisation", Type: FieldTypeString},
				{Key: "companyName", Label: "Company", Type: FieldTypeString},
				{Key: "abuserScore", Label: "Abuser Score", Type: FieldTypeString},
				{Key: "companyDomain", Label: "Domain", Type: FieldTypeString},
				{Key: "vpnService", Label: "VPN Service", Type: FieldTypeString},
				{Key: "vpnType", Label: "VPN Type", Type: FieldTypeString},
				{
					Key:   "companyType",
					Label: "Company Type",
					Type:  FieldTypeBadge,
					Colors: map[string]string{
						"hosting":    "#fb923c",
						"datacenter": "#fb923c",
						"vpn":        "#f87171",
						"tor":        "#f87171",
						"isp":        "#34d399",
						"business":   "#94a3b8",
						"education":  "#94a3b8",
					},
				},
				{Key: "isVPN", Label: "VPN", Type: FieldTypeBool, TrueLabel: "Yes", FalseLabel: "No", TrueColor: "#f87171", FalseColor: "#94a3b8", HideFalse: true},
				{Key: "isProxy", Label: "Proxy", Type: FieldTypeBool, TrueLabel: "Yes", FalseLabel: "No", TrueColor: "#fb923c", FalseColor: "#94a3b8", HideFalse: true},
				{Key: "isTor", Label: "Tor", Type: FieldTypeBool, TrueLabel: "Yes", FalseLabel: "No", TrueColor: "#f87171", FalseColor: "#94a3b8", HideFalse: true},
				{Key: "isDatacenter", Label: "Datacenter", Type: FieldTypeBool, TrueLabel: "Yes", FalseLabel: "No", TrueColor: "#fb923c", FalseColor: "#94a3b8", HideFalse: true},
				{Key: "isCrawler", Label: "Crawler", Type: FieldTypeBool, TrueLabel: "Yes", FalseLabel: "No", TrueColor: "#fbbf24", FalseColor: "#94a3b8", HideFalse: true},
				{Key: "isAbuser", Label: "Abuser", Type: FieldTypeBool, TrueLabel: "Yes", FalseLabel: "No", TrueColor: "#f87171", FalseColor: "#34d399", HideFalse: true},
				{Key: "isBogon", Label: "Bogon", Type: FieldTypeBool, TrueLabel: "Yes", FalseLabel: "No", TrueColor: "#94a3b8", FalseColor: "#94a3b8", HideFalse: true},
				{Key: "isMobile", Label: "Mobile", Type: FieldTypeBool, TrueLabel: "Yes", FalseLabel: "No", TrueColor: "#60a5fa", FalseColor: "#94a3b8", HideFalse: true},
				{Key: "isSatellite", Label: "Satellite", Type: FieldTypeBool, TrueLabel: "Yes", FalseLabel: "No", TrueColor: "#c084fc", FalseColor: "#94a3b8", HideFalse: true},
			},
		},
		TableColumns: []TableColumn{
			{Key: "country", Label: "Country", DefaultVisible: true},
			{Key: "city", Label: "City", DefaultVisible: false},
			{Key: "org", Label: "ASN Org", DefaultVisible: true},
			{Key: "companyType", Label: "Company Type", DefaultVisible: true},
			{Key: "isVPN", Label: "VPN", DefaultVisible: false},
			{Key: "isAbuser", Label: "Abuser", DefaultVisible: false},
		},
	}
}

func (i IPAPIIntegration) Run(ctx context.Context, ioc, apiKey string, useCache bool) (*Result, error) {
	// ipapi.is was previously never cached despite having a table.
	// This wrapper fixes that bug — results are now read and written correctly.
	if useCache {
		if raw := cachedGet(ioc, "IPAPIIS_IP"); raw != "" {
			var r IPAPIResponse
			if err := json.Unmarshal([]byte(raw), &r); err == nil {
				res := ipapiToResult(&r)
				res.FromCache = true
				return res, nil
			}
		}
	}

	r, err := FetchIPAPI(ctx, ioc, apiKey)
	if err != nil {
		return &Result{Error: err.Error()}, nil
	}

	if b, e := json.Marshal(r); e == nil {
		cachedPut(ioc, string(b), "IPAPIIS_IP")
	}
	return ipapiToResult(r), nil
}

func ipapiToResult(r *IPAPIResponse) *Result {
	return &Result{Fields: map[string]any{
		"country":      r.Location.Country,
		"city":         r.Location.City,
		"state":        r.Location.State,
		"timezone":     r.Location.Timezone,
		"localTime":    r.Location.LocalTime,
		"isDST":        r.Location.IsDST,
		"org":          r.ASN.Org,
		"companyName":  r.Company.Name,
		"companyType":  r.Company.Type,
		"companyDomain": r.Company.Domain,
		"abuserScore":  r.Company.AbuserScore,
		"isBogon":      r.IsBogon,
		"isMobile":     r.IsMobile,
		"isSatellite":  r.IsSatellite,
		"isCrawler":    r.IsCrawler,
		"isDatacenter": r.IsDatacenter,
		"isTor":        r.IsTor,
		"isProxy":      r.IsProxy,
		"isVPN":        r.IsVPN,
		"isAbuser":     r.IsAbuser,
		"vpnService":   r.VPN.Service,
		"vpnType":      r.VPN.Type,
		"vpnLastSeen":  r.VPN.LastSeenStr,
	}}
}
