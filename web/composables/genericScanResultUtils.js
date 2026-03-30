// composables/genericScanResultUtils.js
// Shared helpers for adapting generic ScanResult payloads into the
// legacy-shaped frontend view models the current scanner UI expects.

export function stringArray(value) {
    if (Array.isArray(value)) return value.filter(Boolean).map(String);
    if (value && typeof value === 'object') return Object.values(value).filter(Boolean).map(String);
    if (typeof value === 'string' && value) return [value];
    return [];
}

export function cachedAll(result) {
    const cacheHits = result?.cacheHits || {};
    const results = result?.results || {};
    const errors = result?.errors || {};
    const hitCount = Object.keys(cacheHits).filter(key => cacheHits[key]).length;
    return hitCount > 0 && hitCount === Object.keys(results).length + Object.keys(errors).length;
}

export function diagnosticsFromGeneric(result) {
    const names = new Set([
        ...Object.keys(result?.results || {}),
        ...Object.keys(result?.errors || {}),
        ...Object.keys(result?.cacheHits || {}),
    ]);
    if (!names.size) return null;

    const out = {};
    for (const name of names) {
        const fields = result.results?.[name] || {};
        let status = 'ok';
        if (result.errors?.[name]) {
            status = 'error';
        } else if (typeof fields.queryStatus === 'string' && fields.queryStatus) {
            status = fields.queryStatus;
        } else if (fields.notObserved) {
            status = 'not_observed';
        }

        out[name] = {
            cache: result.cacheHits?.[name] ? 'hit' : 'live',
            status,
            error: result.errors?.[name] || '',
        };
    }
    return out;
}
