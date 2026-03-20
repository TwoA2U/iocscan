// integrations/greynoise.go — GreyNoise Community API enrichment for IP addresses.
//
// API docs: https://docs.greynoise.io/docs/using-the-greynoise-community-api
//
// Endpoint: GET https://api.greynoise.io/v3/community/{ip}
// Auth:     "key: {apiKey}" header (optional — 10 lookups/day without a key)
//
// HTTP status handling:
//   200 — found, parse normally
//   404 — IP not observed in GreyNoise dataset, return empty Result (not error)
//   401 — bad API key, return Result{Error}
//   429 — rate limit hit (10/day on free tier), return Result{Error}
//   500 — GreyNoise internal error, return Result{Error}
package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/TwoA2U/iocscan/internal/httpclient"
)

const gnEndpoint = "https://api.greynoise.io/v3/community/"

// ── Raw API response ──────────────────────────────────────────────────────────

type gnResponse struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`
	Riot           bool   `json:"riot"`
	Classification string `json:"classification"`
	Name           string `json:"name"`
	Link           string `json:"link"`
	LastSeen       string `json:"last_seen"`
	Message        string `json:"message"`
}

// ── Fetch function ────────────────────────────────────────────────────────────

// fetchGreyNoise queries the GreyNoise Community API for an IP address.
// Returns (response, notFound, error).
// notFound=true means the IP is simply not in the GreyNoise dataset — not an error.
func fetchGreyNoise(ctx context.Context, ip, apiKey string) (*gnResponse, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gnEndpoint+ip, nil)
	if err != nil {
		return nil, false, fmt.Errorf("greynoise request: %w", err)
	}
	req.Header.Set("User-Agent", "iocscan/1.0")
	if apiKey != "" {
		req.Header.Set("key", apiKey)
	}

	resp, err := httpclient.Client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("greynoise http: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("greynoise read: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// fall through to parse

	case http.StatusNotFound:
		// IP not in GreyNoise dataset — expected, not an error
		return nil, true, nil

	case http.StatusUnauthorized:
		return nil, false, fmt.Errorf("invalid GreyNoise API key")

	case http.StatusTooManyRequests:
		return nil, false, fmt.Errorf("GreyNoise rate limit reached (10 lookups/day on free tier)")

	default:
		return nil, false, fmt.Errorf("GreyNoise HTTP %d: %.120s", resp.StatusCode, string(body))
	}

	var r gnResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, false, fmt.Errorf("greynoise parse: %w", err)
	}
	return &r, false, nil
}

// ── Integration wrapper ───────────────────────────────────────────────────────

type GreyNoise struct{}

func (g GreyNoise) Manifest() Manifest {
	return Manifest{
		Name:     "greynoise",
		Label:    "GreyNoise",
		Icon:     "📡",
		Enabled:  true,
		IOCTypes: []IOCType{IOCTypeIP},
		Auth: AuthConfig{
			KeyRef:   "greynoise",
			Label:    "GreyNoise",
			Optional: true,
		},
		Cache: CacheConfig{
			Table:    "GN_IP",
			TTLHours: 24,
		},
		RiskRules: []RiskRule{
			{
				// classification=malicious → HIGH (context signal, not definitive verdict)
				// classification=suspicious → MEDIUM
				Field: "classification",
				Type:  RiskStringMatch,
				Matches: []RiskMatchRule{
					{Match: "malicious", Level: "HIGH"},
					{Match: "suspicious", Level: "MEDIUM"},
				},
			},
			{
				// noise=true means this IP is actively scanning the internet
				Field:     "noise",
				Type:      RiskBool,
				TrueLevel: "MEDIUM",
			},
		},
		Card: CardDef{
			Title:        "📡 GreyNoise",
			Order:        5,
			LinkTemplate: "https://viz.greynoise.io/ip/{ioc}",
			LinkLabel:    "↗ GreyNoise",
			Fields: []FieldDef{
				{
					Key:   "classification",
					Label: "Classification",
					Type:  FieldTypeBadge,
					Colors: map[string]string{
						"malicious":  "#f87171",
						"suspicious": "#fbbf24",
						"benign":     "#34d399",
						"unknown":    "#4d6480",
					},
				},
				{
					Key:        "noise",
					Label:      "Internet Scanner",
					Type:       FieldTypeBool,
					TrueLabel:  "Yes — Active Scanner",
					FalseLabel: "No",
					TrueColor:  "#fbbf24",
					FalseColor: "#34d399",
				},
				{
					Key:        "riot",
					Label:      "Trusted Service (RIOT)",
					Type:       FieldTypeBool,
					TrueLabel:  "Yes — Known Safe",
					FalseLabel: "No",
					TrueColor:  "#34d399",
					FalseColor: "#94a3b8",
				},
				{
					Key:   "name",
					Label: "Actor / Service",
					Type:  FieldTypeString,
				},
				{
					Key:   "lastSeen",
					Label: "Last Seen",
					Type:  FieldTypeString,
				},
			},
		},
		TableColumns: []TableColumn{
			{Key: "classification", Label: "GN Class", DefaultVisible: true},
			{Key: "noise", Label: "Scanner", DefaultVisible: true},
			{Key: "riot", Label: "RIOT", DefaultVisible: true},
			{Key: "name", Label: "GN Actor", DefaultVisible: false},
			{Key: "lastSeen", Label: "GN Last Seen", DefaultVisible: false},
		},
	}
}

func (g GreyNoise) Run(ctx context.Context, ioc, apiKey string, useCache bool) (*Result, error) {
	if useCache {
		if raw := cachedGet(ioc, "GN_IP"); raw != "" {
			// Check for cached error placeholder first.
			var placeholder struct {
				Message string `json:"message"`
				Error   string `json:"error"`
			}
			if json.Unmarshal([]byte(raw), &placeholder) == nil && placeholder.Error != "" {
				return &Result{Error: placeholder.Error}, nil
			}
			var r gnResponse
			if err := json.Unmarshal([]byte(raw), &r); err == nil {
				res := gnToResult(&r)
				res.FromCache = true
				return res, nil
			}
		}
	}

	r, notFound, err := fetchGreyNoise(ctx, ioc, apiKey)
	if err != nil {
		// Cache rate-limit errors so repeated scans don't burn more daily lookups.
		// Store the error message as a JSON placeholder — cachedGet will serve it
		// on the next scan within the TTL window.
		errPlaceholder := fmt.Sprintf(`{"message":"error","error":%q}`, err.Error())
		cachedPut(ioc, errPlaceholder, "GN_IP")
		return &Result{Error: err.Error()}, nil
	}
	if notFound {
		// IP not in GreyNoise dataset — return empty result, not an error
		// Cache the not-found state so we don't re-query for 24h
		notFoundPlaceholder := `{"message":"not_observed"}`
		cachedPut(ioc, notFoundPlaceholder, "GN_IP")
		return &Result{Fields: map[string]any{
			"classification": "unknown",
			"noise":          false,
			"riot":           false,
			"name":           "",
			"lastSeen":       "",
			"notObserved":    true,
		}}, nil
	}

	if b, e := json.Marshal(r); e == nil {
		cachedPut(ioc, string(b), "GN_IP")
	}
	return gnToResult(r), nil
}

func gnToResult(r *gnResponse) *Result {
	// Normalise classification — API may omit it for not-observed IPs
	classification := r.Classification
	if classification == "" {
		classification = "unknown"
	}
	return &Result{Fields: map[string]any{
		"classification": classification,
		"noise":          r.Noise,
		"riot":           r.Riot,
		"name":           r.Name,
		"lastSeen":       r.LastSeen,
		"notObserved":    false,
	}}
}
