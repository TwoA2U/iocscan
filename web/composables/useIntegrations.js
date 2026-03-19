// composables/useIntegrations.js
// ─────────────────────────────────────────────────────────────────────────────
// Fetches and caches integration manifests from GET /api/integrations.
// Called once at app boot (from main.js); all components read from the
// reactive refs exported here — no component ever fetches directly.
//
// The manifest list drives:
//   - IntegrationCard.js  (card layout, field types, link templates)
//   - ipTableColumns      (dynamic table columns for IP scan results)
//   - hashTableColumns    (dynamic table columns for hash scan results)
//   - allAuthConfigs      (API key input labels in ScanSettings)
//
// Uses Vue 3 GLOBAL build (window.Vue) — no bundler required.
// ─────────────────────────────────────────────────────────────────────────────

const { ref, computed, shallowRef } = Vue;

// ── State ─────────────────────────────────────────────────────────────────────

// manifests holds every integration Manifest returned by /api/integrations.
// shallowRef avoids deep reactivity overhead on read-only JSON data.
export const manifests      = shallowRef([]);
export const manifestsReady = ref(false);
export const manifestsError = ref('');

// ── Derived views ─────────────────────────────────────────────────────────────

// ipManifests: enabled integrations that support IP address enrichment.
export const ipManifests = computed(() =>
    manifests.value.filter(m => m.enabled && Array.isArray(m.iocTypes) && m.iocTypes.includes('ip'))
);

// hashManifests: enabled integrations that support file hash enrichment.
export const hashManifests = computed(() =>
    manifests.value.filter(m => m.enabled && Array.isArray(m.iocTypes) && m.iocTypes.includes('hash'))
);

// allAuthConfigs: unique AuthConfig objects across all integrations, deduplicated
// by keyRef. Used to build API key inputs in ScanSettings automatically.
export const allAuthConfigs = computed(() => {
    const seen = new Set();
    const out  = [];
    for (const m of manifests.value) {
        const keyRef = m.auth?.keyRef;
        if (!keyRef || seen.has(keyRef)) continue;
        seen.add(keyRef);
        out.push(m.auth);
    }
    return out;
});

// ipTableColumns: flat ordered list of table column descriptors for IP results.
// Each entry carries the originating integration name so the table renderer
// can look up the result value in sr.results[integration][key].
export const ipTableColumns = computed(() => {
    const cols = [];
    for (const m of ipManifests.value) {
        for (const col of (m.tableColumns ?? [])) {
            cols.push({ ...col, integration: m.name });
        }
    }
    return cols;
});

// hashTableColumns: same as ipTableColumns but for hash integrations.
export const hashTableColumns = computed(() => {
    const cols = [];
    for (const m of hashManifests.value) {
        for (const col of (m.tableColumns ?? [])) {
            cols.push({ ...col, integration: m.name });
        }
    }
    return cols;
});

// ── Lookup helpers ────────────────────────────────────────────────────────────

// getManifest returns the manifest for a given integration name, or null.
export function getManifest(name) {
    return manifests.value.find(m => m.name === name) ?? null;
}

// ── Fetch ─────────────────────────────────────────────────────────────────────

// loadManifests fetches /api/integrations once and populates all reactive refs.
// Idempotent: if manifests are already loaded it returns without a network call.
export async function loadManifests() {
    if (manifestsReady.value) return;

    try {
        const res = await fetch('/api/integrations', {
            headers: { Accept: 'application/json' },
        });
        if (!res.ok) throw new Error(`/api/integrations returned HTTP ${res.status}`);

        const data = await res.json();
        if (!Array.isArray(data)) throw new Error('Expected array from /api/integrations');

        manifests.value      = data;
        manifestsReady.value = true;
        manifestsError.value = '';
    } catch (err) {
        manifestsError.value = String(err.message ?? err);
        console.error('[useIntegrations] loadManifests:', err);
    }
}

// ── Rendering helpers ─────────────────────────────────────────────────────────
// Used by IntegrationCard.js and table cell renderers for consistent styling.

// scoreBarColor picks the CSS color for a score_bar field value.
// Thresholds must be ordered highest-gte first (same contract as Go manifests).
export function scoreBarColor(thresholds, value) {
    if (!Array.isArray(thresholds) || thresholds.length === 0) return '#94a3b8';
    const n = Number(value);
    if (Number.isNaN(n)) return '#94a3b8';
    for (const t of thresholds) {
        if (n >= t.gte) return t.color;
    }
    return thresholds[thresholds.length - 1]?.color ?? '#94a3b8';
}

// badgeColor picks the CSS color for a badge field value from the colors map.
// Falls back to neutral slate (#4d6480) for unknown values.
export function badgeColor(colors, value) {
    if (!colors || typeof colors !== 'object') return '#4d6480';
    return colors[String(value)] ?? '#4d6480';
}

// buildLinkUrl substitutes {ioc} in a linkTemplate with the actual IOC value.
export function buildLinkUrl(template, ioc) {
    if (!template) return '';
    return template.replace('{ioc}', encodeURIComponent(ioc));
}