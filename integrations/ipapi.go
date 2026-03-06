// integrations/ipapi.go — ipapi.is geo and ASN enrichment for IP addresses.
//
// API docs: https://ipapi.is/
//
// Endpoint: GET https://api.ipapi.is/?q={ip}[&key={apiKey}]
// Auth: optional key query parameter (free tier works without one).
package integrations

import (
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
func FetchIPAPI(ip, apiKey string) (*IPAPIResponse, error) {
	reqURL := fmt.Sprintf("%s/?q=%s", ipapiEndpoint, url.QueryEscape(ip))
	if apiKey != "" {
		reqURL += "&key=" + url.QueryEscape(apiKey)
	}

	body, err := httpclient.DoGet(reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("ipapi.is: %w", err)
	}

	var resp IPAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("ipapi.is parse: %w", err)
	}
	return &resp, nil
}
