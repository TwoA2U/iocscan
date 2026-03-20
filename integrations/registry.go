// integrations/registry.go — Plugin registry.
//
// All() is the single source of truth for every registered integration.
// Adding a new integration = uncomment (or add) one line in the All() slice.
//
// Public API:
//   All()              → every registered Integration
//   ForIOCType(t)      → enabled integrations supporting a given IOC type
//   Manifests()        → all manifests; consumed by GET /api/integrations
//   CacheTables()      → all non-empty cache table names; consumed by InitDB()
package integrations

import "sync"

// ── Registry ──────────────────────────────────────────────────────────────────

var (
	registryOnce sync.Once
	registry     []Integration
)

// All returns every registered integration in declaration order.
// The slice is initialized exactly once (sync.Once); subsequent calls
// return the cached slice with no allocation.
//
// To add a new integration:
//  1. Create integrations/yourvendor.go implementing Integration
//  2. Uncomment or append &YourVendor{} below
//  3. Done — InitDB(), /api/integrations, and the orchestrator all
//     pick it up automatically on next startup
func All() []Integration {
	registryOnce.Do(func() {
		registry = []Integration{
			// ── IP integrations ───────────────────────────────────────────
			&VirusTotalIP{},
			&AbuseIPDBIntegration{},
			&IPAPIIntegration{},
			&ThreatFoxIPIntegration{},
			&GreyNoise{},

			// ── Hash integrations ─────────────────────────────────────────
			&VirusTotalHash{},
			&MalwareBazaarIntegration{},
			&ThreatFoxHashIntegration{},

			// ── Domain integrations ───────────────────────────────────────
			&VirusTotalDomain{},
			&ThreatFoxDomainIntegration{},

			// ── Future integrations (uncomment to enable) ─────────────────
			// &Shodan{},
			// &OTX{},
			// &URLHaus{},
		}
	})
	return registry
}

// ── Filtered views ────────────────────────────────────────────────────────────

// ForIOCType returns all enabled integrations that support the given IOC type.
// Disabled integrations (Manifest().Enabled == false) are excluded.
// The returned slice is a new allocation on every call; callers may freely
// range over it without holding a lock.
func ForIOCType(t IOCType) []Integration {
	all := All()
	out := make([]Integration, 0, len(all))
	for _, ig := range all {
		m := ig.Manifest()
		if !m.Enabled {
			continue
		}
		for _, supported := range m.IOCTypes {
			if supported == t {
				out = append(out, ig)
				break
			}
		}
	}
	return out
}

// Manifests returns the Manifest of every registered integration in order.
// Used by the GET /api/integrations handler to serve the full metadata
// payload to the Vue frontend at boot time.
func Manifests() []Manifest {
	all := All()
	out := make([]Manifest, len(all))
	for i, ig := range all {
		out[i] = ig.Manifest()
	}
	return out
}

// CacheTables returns the unique, non-empty cache table names declared by
// all registered integrations. Used by InitDB() to create tables and by
// allowedTables to build the SQL injection whitelist — both dynamically,
// so neither needs updating when a new integration is added.
func CacheTables() []string {
	all := All()
	seen := make(map[string]bool, len(all))
	out := make([]string, 0, len(all))
	for _, ig := range all {
		t := ig.Manifest().Cache.Table
		if t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}
