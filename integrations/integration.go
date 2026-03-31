// integrations/integration.go — Core plugin interface and shared types.
//
// Every threat-intelligence vendor implements the Integration interface.
// Its Manifest() method returns static metadata that self-configures:
//
//   - SQLite cache table registration   (no manual allowedTables edits)
//   - GET /api/integrations endpoint    (Vue frontend fetches at boot)
//   - IntegrationCard.js rendering      (FieldDef slice drives the card)
//   - Table column visibility           (replaces hardcoded useIPResults/useHashResults)
//   - Risk scoring                      (replaces hardcoded assessRisk functions)
//   - ScanSettings UI                   (auth labels auto-generated from AuthConfig)
//
// Adding a new integration = create 1 file + add 1 line to registry.go.
// No other files need to change.
//
// Dependency graph:
//   integration.go  ← registry.go ← orchestrator.go ← web.go
//                                  ↑
//                   (each vendor file also imports this package)
package integrations

import (
	"context"
	"time"
)

// ── IOC Types ─────────────────────────────────────────────────────────────────

// IOCType identifies what kind of indicator an integration processes.
// Used in Manifest.IOCTypes and by the registry ForIOCType() filter.
type IOCType string

const (
	IOCTypeIP     IOCType = "ip"
	IOCTypeHash   IOCType = "hash"
	IOCTypeDomain IOCType = "domain"
	IOCTypeURL    IOCType = "url"
)

// ── Frontend Field Rendering ──────────────────────────────────────────────────

// FieldType controls how IntegrationCard.js renders a single result field.
// Each constant maps to a rendering branch in the generic card component.
type FieldType string

const (
	// FieldTypeString renders the raw value as plain text.
	FieldTypeString FieldType = "string"

	// FieldTypeNumber renders the value right-aligned as a number.
	FieldTypeNumber FieldType = "number"

	// FieldTypeBool renders a colored Yes/No label.
	// Use TrueLabel/FalseLabel to override the display text.
	// Use TrueColor/FalseColor to override the CSS color.
	FieldTypeBool FieldType = "bool"

	// FieldTypeBadge renders a colored label pill.
	// Colors maps each possible value string to a CSS color string.
	// Unknown values fall back to a neutral gray (#4d6480).
	FieldTypeBadge FieldType = "badge"

	// FieldTypeScoreBar renders a percentage progress bar.
	// Bar color is driven by Thresholds (highest-first evaluation).
	FieldTypeScoreBar FieldType = "score_bar"

	// FieldTypeTags renders a []string value as a row of pill chips.
	FieldTypeTags FieldType = "tags"

	// FieldTypeLink renders the value as a clickable external hyperlink.
	// The value itself is used as the href.
	FieldTypeLink FieldType = "link"
)

// ScoreThreshold maps a minimum score value to a CSS color string.
// Used by FieldTypeScoreBar. Thresholds are evaluated highest-first;
// the color of the first matching threshold is applied.
//
// Example (0-100 abuse confidence score):
//
//	[]ScoreThreshold{
//	    {Gte: 75, Color: "#f87171"},  // red    — critical
//	    {Gte: 40, Color: "#fb923c"},  // orange — high
//	    {Gte: 1,  Color: "#fbbf24"},  // yellow — low
//	    {Gte: 0,  Color: "#34d399"},  // green  — clean
//	}
type ScoreThreshold struct {
	Gte   int    `json:"gte"`
	Color string `json:"color"`
}

// FieldDef describes one key-value row rendered inside an integration's card.
// The Key must exactly match the map[string]any key in Result.Fields.
type FieldDef struct {
	// Key is the field name as it appears in Result.Fields.
	Key string `json:"key"`

	// Label is the human-readable name shown in the card row and table header.
	Label string `json:"label"`

	// Type controls which rendering branch IntegrationCard.js uses.
	Type FieldType `json:"type"`

	// Colors — FieldTypeBadge only.
	// Maps value strings to CSS color strings (e.g. "#f87171").
	// Values absent from the map fall back to "#4d6480" (neutral slate).
	Colors map[string]string `json:"colors,omitempty"`

	// Thresholds — FieldTypeScoreBar only. Evaluated highest-first.
	Thresholds []ScoreThreshold `json:"thresholds,omitempty"`

	// Bool display overrides — FieldTypeBool only.
	TrueLabel  string `json:"trueLabel,omitempty"`
	FalseLabel string `json:"falseLabel,omitempty"`
	TrueColor  string `json:"trueColor,omitempty"`
	FalseColor string `json:"falseColor,omitempty"`

	// HideFalse skips rendering this bool field when the value is false.
	// Useful for capability/flag style fields where only positive findings
	// should appear in the generic card.
	HideFalse bool `json:"hideFalse,omitempty"`
}

// ── Card Definition ───────────────────────────────────────────────────────────

// CardDef describes the card that IntegrationCard.js renders for this integration.
// A card is a bordered panel in the scan result view showing key-value rows
// for each field in the Fields slice.
type CardDef struct {
	// Title is displayed in the card header (e.g. "🚨 AbuseIPDB").
	Title string `json:"title"`

	// Order controls the card's position in the grid (lower = earlier).
	// Gaps are fine — cards are sorted ascending, not indexed.
	Order int `json:"order"`

	// LinkTemplate is a URL shown as a ↗ link in the card header.
	// The placeholder {ioc} is substituted with the scanned indicator value.
	// e.g. "https://www.virustotal.com/gui/ip-address/{ioc}"
	LinkTemplate string `json:"linkTemplate,omitempty"`

	// LinkLabel is the anchor text shown for the header link.
	// e.g. "↗ VT", "↗ AbuseIPDB"
	LinkLabel string `json:"linkLabel,omitempty"`

	// Fields is the ordered list of key-value rows in the card body.
	// Rows whose key is absent or nil in Result.Fields are silently skipped.
	Fields []FieldDef `json:"fields"`
}

// ── Table Columns ─────────────────────────────────────────────────────────────

// TableColumn describes one column in the results table for this integration.
// The Key must match a key in Result.Fields (values are rendered as plain text).
type TableColumn struct {
	// Key is the Result.Fields key used to populate this column's cells.
	Key string `json:"key"`

	// Label is the column header text.
	Label string `json:"label"`

	// DefaultVisible controls whether the column appears on first page load.
	// Columns can be toggled by the user via ColumnDrawer regardless of this value.
	DefaultVisible bool `json:"defaultVisible"`
}

// ── Risk Scoring ──────────────────────────────────────────────────────────────

// RiskRuleType determines how a RiskRule evaluates a field value.
type RiskRuleType string

const (
	// RiskThreshold triggers when a numeric field value >= the Gte threshold.
	RiskThreshold RiskRuleType = "threshold"

	// RiskStringMatch triggers when a string field value exactly equals a Match.
	RiskStringMatch RiskRuleType = "string_match"

	// RiskBool triggers when a boolean field value is true.
	RiskBool RiskRuleType = "bool"
)

// RiskLevelWeight maps risk level names to numeric severity weights.
// Higher weight = higher severity. Used by EvaluateRisk to surface the worst
// level found across all rules and all integrations in a scan.
var RiskLevelWeight = map[string]int{
	"CRITICAL": 4,
	"HIGH":     3,
	"MEDIUM":   2,
	"LOW":      1,
	"CLEAN":    0,
}

// RiskThresholdRule maps a minimum numeric score to a risk level string.
// Multiple thresholds in a RiskRule are evaluated highest-Gte-first;
// the first match wins (same pattern as a switch-case).
type RiskThresholdRule struct {
	Gte   int    `json:"gte"`
	Level string `json:"level"` // one of: "CRITICAL","HIGH","MEDIUM","LOW","CLEAN"
}

// RiskMatchRule maps a specific string value to a risk level string.
type RiskMatchRule struct {
	Match string `json:"match"`
	Level string `json:"level"`
}

// RiskRule describes one condition that contributes to the overall risk level.
// The orchestrator calls EvaluateRisk(manifest.RiskRules, result.Fields) for
// every integration and keeps the highest level found across all of them.
type RiskRule struct {
	// Field is the Result.Fields key whose value is evaluated.
	Field string       `json:"field"`
	Type  RiskRuleType `json:"type"`

	// Thresholds — RiskThreshold only. Must be ordered highest-Gte first.
	Thresholds []RiskThresholdRule `json:"thresholds,omitempty"`

	// Matches — RiskStringMatch only.
	Matches []RiskMatchRule `json:"matches,omitempty"`

	// TrueLevel — RiskBool only. Risk level emitted when the field is true.
	TrueLevel string `json:"trueLevel,omitempty"`
}

// ── Auth Configuration ────────────────────────────────────────────────────────

// AuthConfig describes how the integration's API key is sourced and surfaced.
type AuthConfig struct {
	// KeyRef is the canonical key name used everywhere:
	//   - Lookup key in the keys map[string]string passed to Run()
	//   - Field identifier in the ScanSettings Vue component
	//   - Config file viper key prefix (via loadAPIKeys helper)
	// Convention: short lowercase names — "vt", "abuse", "ipapi", "abusech".
	KeyRef string `json:"keyRef"`

	// Label is the human-readable name shown in the ScanSettings input.
	// e.g. "VirusTotal", "AbuseIPDB", "GreyNoise"
	Label string `json:"label"`

	// Optional marks integrations that function without a key
	// (e.g. ThreatFox public tier, ipapi.is free tier).
	// The ScanSettings UI renders these fields with an "(optional)" hint.
	Optional bool `json:"optional"`
}

// ── Cache Configuration ───────────────────────────────────────────────────────

// CacheConfig describes the SQLite cache table for this integration.
// InitDB() reads every registered integration's CacheConfig at startup
// and automatically creates any missing tables and indexes. No manual
// DDL or allowedTables entries are needed.
type CacheConfig struct {
	// Table is the SQLite table name. Must be unique across all integrations.
	// Convention: "{VENDOR}_{IOCTYPE}" in UPPER_SNAKE_CASE.
	// e.g. "VT_IP", "ABUSE_IP", "GN_IP", "TF_HASH"
	// Set to "" to disable caching for this integration.
	Table string `json:"table"`

	// TTL is the in-process cache duration used when checking freshness.
	// Not serialized to JSON (set programmatically in Manifest()).
	// Zero means use the global cacheMaxAge default from common.go.
	TTL time.Duration `json:"-"`

	// TTLHours is the serialized version of TTL for the /api/integrations
	// response so the frontend can display "cached for X hours" info.
	TTLHours int `json:"ttlHours"`
}

// ── Manifest ──────────────────────────────────────────────────────────────────

// Manifest is the complete static metadata for one integration.
//
// Returned by Integration.Manifest() which is called once per integration
// at registry initialization. The returned value is never mutated after that.
//
// Manifest self-configures the entire system:
//
//	Cache      → InitDB() creates Cache.Table; cache validation is manifest-derived
//	API        → /api/integrations serializes all manifests as JSON to the frontend
//	Cards      → IntegrationCard.js renders Card.Fields dynamically
//	Table cols → useIntegrations.js builds column definitions from TableColumns
//	Settings   → ScanSettings.js generates API key inputs from Auth
//	Risk       → orchestrator calls EvaluateRisk(RiskRules, result.Fields)
type Manifest struct {
	// Identity fields
	Name     string    `json:"name"`     // machine name, lowercase: "abuseipdb", "greynoise"
	Label    string    `json:"label"`    // display name: "AbuseIPDB", "GreyNoise"
	Icon     string    `json:"icon"`     // emoji used in card headers and nav: "🚨", "📡"
	Enabled  bool      `json:"enabled"`  // false = skipped by ForIOCType() entirely
	IOCTypes []IOCType `json:"iocTypes"` // IOC types this integration handles

	// Infrastructure
	Auth  AuthConfig  `json:"auth"`
	Cache CacheConfig `json:"cache"`

	// Frontend rendering
	Card         CardDef       `json:"card"`
	TableColumns []TableColumn `json:"tableColumns"`

	// Risk scoring — all rules evaluated by EvaluateRisk() after Run() returns.
	// Leave nil if the integration does not contribute to risk scoring.
	RiskRules []RiskRule `json:"riskRules,omitempty"`
}

// ── Result ────────────────────────────────────────────────────────────────────

// Result is the normalized output of a single integration's Run() call.
//
// Field keys must exactly match the FieldDef.Key values in Manifest.Card.Fields
// so IntegrationCard.js can render them generically without hardcoded names.
//
// Key naming convention: camelCase matching existing JSON field names where
// possible to ease migration from older hardcoded frontend response shapes.
// e.g. "confidenceScore", "malicious", "queryStatus", "tags"
type Result struct {
	// Fields holds all vendor data extracted for this IOC.
	// Values may be any JSON-serializable type:
	//   string, int, float64, bool, []string, nil
	// Nil and missing values are silently skipped by the card renderer.
	Fields map[string]any `json:"fields"`

	// Error is non-empty when the vendor call failed but the scan should
	// continue. The orchestrator records this in ScanResult.Errors and
	// keeps collecting results from the other integrations (partial result).
	//
	// Return a Go error from Run() ONLY for unrecoverable programming errors
	// (JSON marshal failures, nil dereferences). For all vendor HTTP failures
	// (network error, bad status, missing API key) set this field instead.
	Error string `json:"error,omitempty"`

	// FromCache is true when this result was served from the local SQLite
	// cache rather than a live vendor API call.
	FromCache bool `json:"fromCache"`
}

// ── Integration Interface ─────────────────────────────────────────────────────

// Integration is the single interface every vendor plugin must implement.
//
// To add a new integration:
//  1. Create integrations/yourvendor.go
//  2. Define a zero-value struct:    type GreyNoise struct{}
//  3. Implement Manifest()           return a fully-populated Manifest value
//  4. Implement Run()                call vendor API, return &Result{Fields: ...}
//  5. Register in registry.go        add &GreyNoise{} to All() slice
//
// That is the complete process. InitDB(), cache validation, /api/integrations,
// card rendering, table columns, risk scoring, and ScanSettings all
// self-configure from the Manifest. No other files need to change.
type Integration interface {
	// Manifest returns the static metadata for this integration.
	// Called once at startup; the result is cached by the registry.
	// Must be safe to call concurrently; return a value, not a pointer.
	Manifest() Manifest

	// Run performs the enrichment for a single IOC value.
	//
	//   ioc      — the indicator string (IP, hash hex, domain, etc.)
	//   apiKey   — value from keys[Manifest().Auth.KeyRef]; "" if Optional
	//   useCache — check SQLite cache before making a network call when true
	//
	// Implementations MUST:
	//   - Pass ctx to every outbound HTTP call (respect cancellation)
	//   - Set Result.Error for recoverable vendor failures instead of
	//     returning a Go error, so the orchestrator collects partial results
	//   - Only return a Go error for unrecoverable internal failures
	Run(ctx context.Context, ioc string, apiKey string, useCache bool) (*Result, error)
}

// ── Risk Evaluation ───────────────────────────────────────────────────────────

// EvaluateRisk evaluates all rules against fields and returns the
// highest-severity risk level string found, or "" if nothing matches.
//
// The orchestrator calls this once per integration after Run() returns,
// then keeps the globally highest level across all integrations:
//
//	best := "CLEAN"
//	for _, ig := range plugins {
//	    level := integrations.EvaluateRisk(ig.Manifest().RiskRules, pr.result.Fields)
//	    if integrations.RiskLevelWeight[level] > integrations.RiskLevelWeight[best] {
//	        best = level
//	    }
//	}
func EvaluateRisk(rules []RiskRule, fields map[string]any) string {
	best := ""
	bestWeight := -1

	for _, rule := range rules {
		val, ok := fields[rule.Field]
		if !ok || val == nil {
			continue
		}

		var level string

		switch rule.Type {

		case RiskThreshold:
			n, ok := toInt(val)
			if !ok {
				continue
			}
			// Thresholds must be ordered highest-Gte first in the manifest.
			// We evaluate in order and take the first match, like a switch-case.
			for _, t := range rule.Thresholds {
				if n >= t.Gte {
					level = t.Level
					break
				}
			}

		case RiskStringMatch:
			s, ok := val.(string)
			if !ok {
				continue
			}
			for _, m := range rule.Matches {
				if s == m.Match {
					level = m.Level
					break
				}
			}

		case RiskBool:
			b, ok := val.(bool)
			if !ok {
				continue
			}
			if b && rule.TrueLevel != "" {
				level = rule.TrueLevel
			}
		}

		if w, exists := RiskLevelWeight[level]; exists && w > bestWeight {
			best = level
			bestWeight = w
		}
	}

	return best
}

// toInt converts common numeric types to int for threshold evaluation.
// JSON numbers decoded into map[string]any default to float64,
// so that case is listed first for performance.
func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case float32:
		return int(n), true
	case int:
		return n, true
	case int32:
		return int(n), true
	case int64:
		return int(n), true
	}
	return 0, false
}
