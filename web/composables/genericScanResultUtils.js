// composables/genericScanResultUtils.js
// Shared helpers for adapting generic ScanResult payloads into the
// legacy-shaped frontend view models the current scanner UI expects.

import { getManifestsForIOCType } from './useIntegrations.js?v=12';

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

export function hasRenderableIntegrationCardData(result, error = '') {
    if (error) return true;
    if (!result || typeof result !== 'object') return false;

    return Object.values(result).some(value => {
        if (value == null) return false;
        if (typeof value === 'string') return value !== '';
        if (Array.isArray(value)) return value.length > 0;
        return true;
    });
}

export function buildFallbackIntegrationCards(rawResult, iocType, excludedNames = []) {
    if (!rawResult || typeof rawResult !== 'object' || rawResult.iocType !== iocType || !rawResult.results) {
        return [];
    }

    const excluded = excludedNames instanceof Set ? excludedNames : new Set(excludedNames);
    const results = rawResult.results || {};
    const errors = rawResult.errors || {};

    return getManifestsForIOCType(iocType)
        .filter(manifest => !excluded.has(manifest.name))
        .map(manifest => ({
            name: manifest.name,
            manifest,
            ioc: rawResult.ioc || '',
            result: results[manifest.name] || null,
            error: errors[manifest.name] || '',
        }))
        .filter(card => hasRenderableIntegrationCardData(card.result, card.error));
}
