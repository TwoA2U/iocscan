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
				{Key: "org", Label: "Organisation", Type: FieldTypeString},
				{Key: "companyName", Label: "Company", Type: FieldTypeString},
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
			},
		},
		TableColumns: []TableColumn{
			{Key: "country", Label: "Country", DefaultVisible: true},
			{Key: "city", Label: "City", DefaultVisible: false},
			{Key: "org", Label: "ASN Org", DefaultVisible: true},
			{Key: "companyType", Label: "Company Type", DefaultVisible: true},
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
		"country":     r.Location.Country,
		"city":        r.Location.City,
		"state":       r.Location.State,
		"timezone":    r.Location.Timezone,
		"org":         r.ASN.Org,
		"companyName": r.Company.Name,
		"companyType": r.Company.Type,
	}}
}
