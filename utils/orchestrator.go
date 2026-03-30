// utils/orchestrator.go — Generic IOC enrichment orchestrator.
//
// Scan() replaces the hardcoded goroutine fan-out in iputil.go and hashutil.go.
// It runs every enabled integration for the given IOC type concurrently,
// collects partial results, evaluates risk across all manifests, and returns
// a single ScanResult.
//
// Public API:
//   Scan(ctx, ioc, iocType, keys, useCache) (*ScanResult, error)
//   BuildKeys(vtKey, abuseKey, ipapiKey, abusechKey string) map[string]string
package utils

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/TwoA2U/iocscan/integrations"
)

// ── Output type ───────────────────────────────────────────────────────────────

// ScanResult is the unified output of a full IOC enrichment run.
//
// Results is keyed by integration name (Manifest.Name), so callers can do:
//
//	abuseFields := result.Results["abuseipdb"]
//	vtFields    := result.Results["virustotal_ip"]
//
// This replaces fixed per-vendor response structs with a generic map that
// extends automatically when new integrations are added.
type ScanResult struct {
	IOC       string `json:"ioc"`
	IOCType   string `json:"iocType"`
	RiskLevel string `json:"riskLevel"`

	// Results holds every integration's Result.Fields, keyed by Manifest.Name.
	// Only integrations that returned data (no error) are present.
	Results map[string]map[string]any `json:"results"`

	// Errors holds per-integration error messages for failed calls.
	// A scan can succeed overall while individual integrations fail.
	Errors map[string]string `json:"errors,omitempty"`

	// CacheHits records which integrations served their result from the
	// local SQLite cache rather than a live API call.
	// true = cached, false/absent = live API call.
	CacheHits map[string]bool `json:"cacheHits,omitempty"`
}

// ── Key helper ────────────────────────────────────────────────────────────────

// BuildKeys constructs the keys map consumed by Scan() from the individual
// key strings used throughout the existing codebase. Call this from any
// handler or processor that still receives keys as separate arguments.
//
// KeyRef values match the AuthConfig.KeyRef declared in each integration's
// Manifest: "vt", "abuse", "ipapi", "abusech".
func BuildKeys(vtKey, abuseKey, ipapiKey, abusechKey string) map[string]string {
	return map[string]string{
		"vt":      vtKey,
		"abuse":   abuseKey,
		"ipapi":   ipapiKey,
		"abusech": abusechKey,
	}
}

// ── Orchestrator ──────────────────────────────────────────────────────────────

// Scan runs all enabled integrations for iocType concurrently and returns
// a unified ScanResult.
//
// Keys is a map of KeyRef → API key (build with BuildKeys()).
// A missing or empty key is passed as "" to Run(); integrations that declared
// Optional: true in their AuthConfig handle that gracefully.
//
// Scan enforces a 25-second total timeout regardless of individual vendor
// latency. If ctx is already cancelled when Scan is called it returns
// immediately with an error.
func Scan(
	ctx context.Context,
	ioc string,
	iocType integrations.IOCType,
	keys map[string]string,
	useCache bool,
) (*ScanResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("scan cancelled before start: %w", err)
	}

	// Cap total enrichment time across all vendors.
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	ioc = strings.TrimSpace(ioc)

	// Guard against nil keys map — callers should use BuildKeys() but
	// a nil map read in Go is safe; only writes panic. We make defensively
	// so any future write path is also safe.
	if keys == nil {
		keys = make(map[string]string)
	}

	plugins := integrations.ForIOCType(iocType)

	if len(plugins) == 0 {
		return &ScanResult{
			IOC:       ioc,
			IOCType:   string(iocType),
			RiskLevel: "CLEAN",
			Results:   make(map[string]map[string]any),
		}, nil
	}

	// ── Concurrent fan-out ────────────────────────────────────────────────────

	type pluginResult struct {
		name   string
		result *integrations.Result
	}

	ch := make(chan pluginResult, len(plugins))
	var wg sync.WaitGroup

	for _, plugin := range plugins {
		wg.Add(1)
		go func(p integrations.Integration) {
			defer wg.Done()
			m := p.Manifest()
			apiKey := keys[m.Auth.KeyRef]

			r, err := p.Run(ctx, ioc, apiKey, useCache)
			if err != nil {
				// Unrecoverable internal error — wrap in a Result so the
				// channel always receives exactly one value per plugin.
				r = &integrations.Result{Error: err.Error()}
			}
			if r == nil {
				r = &integrations.Result{Error: "integration returned nil result"}
			}
			ch <- pluginResult{name: m.Name, result: r}
		}(plugin)
	}

	// Close channel once all goroutines finish so the range below terminates.
	go func() {
		wg.Wait()
		close(ch)
	}()

	// ── Collect results ───────────────────────────────────────────────────────

	out := &ScanResult{
		IOC:       ioc,
		IOCType:   string(iocType),
		Results:   make(map[string]map[string]any, len(plugins)),
		Errors:    make(map[string]string),
		CacheHits: make(map[string]bool),
	}

	for pr := range ch {
		if pr.result.Error != "" {
			out.Errors[pr.name] = pr.result.Error
		} else {
			out.Results[pr.name] = pr.result.Fields
			if pr.result.FromCache {
				out.CacheHits[pr.name] = true
			}
		}
	}

	// Remove Errors and CacheHits maps from output if empty — keeps JSON clean.
	if len(out.Errors) == 0 {
		out.Errors = nil
	}
	if len(out.CacheHits) == 0 {
		out.CacheHits = nil
	}

	// Check for context cancellation after collecting — if the caller gave up
	// we still have partial results but signal that the scan was cut short.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("scan cancelled: %w", err)
	}

	// ── Risk evaluation ───────────────────────────────────────────────────────

	out.RiskLevel = evaluateOverallRisk(plugins, out.Results)

	return out, nil
}

// evaluateOverallRisk iterates every enabled plugin's RiskRules against
// its corresponding result fields and returns the highest level found.
// Falls back to "CLEAN" if no rules match.
func evaluateOverallRisk(
	plugins []integrations.Integration,
	results map[string]map[string]any,
) string {
	best := "CLEAN"
	bestWeight := integrations.RiskLevelWeight["CLEAN"]

	for _, p := range plugins {
		m := p.Manifest()
		if len(m.RiskRules) == 0 {
			continue
		}
		fields, ok := results[m.Name]
		if !ok {
			continue // integration errored — skip its risk rules
		}
		level := integrations.EvaluateRisk(m.RiskRules, fields)
		if level == "" {
			continue
		}
		if w, exists := integrations.RiskLevelWeight[level]; exists && w > bestWeight {
			best = level
			bestWeight = w
		}
	}

	return best
}

// ── Numeric conversion helper ─────────────────────────────────────────────────

// toInt converts common numeric types to int for field extraction and
// risk threshold evaluation. JSON numbers decoded into map[string]any
// default to float64, so that case is listed first for performance.
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
