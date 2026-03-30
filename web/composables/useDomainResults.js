// web/composables/useDomainResults.js
// ─────────────────────────────────────────────────────────────────────────────
// State, computed, table, cell rendering, and export logic for domain results.
// Follows the same pattern as useIPResults.js and useHashResults.js.
// Uses Vue 3 GLOBAL build (window.Vue) — no bundler required.
// ─────────────────────────────────────────────────────────────────────────────

import { highlightJSON } from '../utils.js';

const { ref, computed } = Vue;

// ─── State ────────────────────────────────────────────────────────────────────

export const allDomainResults  = ref([]);
export const activeDomainIdx   = ref(0);
export const domainSortCol     = ref('#');
export const domainSortAsc     = ref(true);
export const domainError       = ref('');
export const domainBulkCount   = ref(0);
export const isDomainLoading   = ref(false);
export const domainInputText   = ref('');
export const domainUseCache    = ref(true);
export const domainView        = ref('cards');

function isGenericDomainResult(result) {
    return !!(result && typeof result === 'object' && result.ioc && result.iocType === 'domain' && result.results);
}

function stringArray(value) {
    if (Array.isArray(value)) return value.filter(Boolean).map(String);
    if (value && typeof value === 'object') return Object.values(value).filter(Boolean).map(String);
    if (typeof value === 'string' && value) return [value];
    return [];
}

function cachedAll(result) {
    const cacheHits = result?.cacheHits || {};
    const results = result?.results || {};
    const errors = result?.errors || {};
    const hitCount = Object.keys(cacheHits).filter(key => cacheHits[key]).length;
    return hitCount > 0 && hitCount === Object.keys(results).length + Object.keys(errors).length;
}

function diagnosticsFromGeneric(result) {
    const names = new Set([
        ...Object.keys(result?.results || {}),
        ...Object.keys(result?.errors || {}),
        ...Object.keys(result?.cacheHits || {}),
    ]);
    if (!names.size) return null;

    const out = {};
    for (const name of names) {
        const fields = result.results?.[name] || {};
        out[name] = {
            cache: result.cacheHits?.[name] ? 'hit' : 'live',
            status: result.errors?.[name]
                ? 'error'
                : (fields.queryStatus || 'ok'),
            error: result.errors?.[name] || '',
        };
    }
    return out;
}

function adaptGenericDomainResult(result) {
    if (!isGenericDomainResult(result)) return result;

    const vt = result.results?.virustotal_domain || {};
    const tf = result.results?.threatfox_domain || null;

    return {
        domain: result.ioc,
        riskLevel: result.riskLevel,
        cached: cachedAll(result),
        cacheHits: result.cacheHits || null,
        diagnostics: diagnosticsFromGeneric(result),
        links: {
            virustotal: `https://www.virustotal.com/gui/domain/${result.ioc}`,
            threatfox: `https://threatfox.abuse.ch/browse.php?search=ioc%3A${result.ioc}`,
        },
        virustotal: {
            malicious: vt.malicious || 0,
            suspicious: vt.suspicious || 0,
            harmless: vt.harmless || 0,
            undetected: vt.undetected || 0,
            reputation: vt.reputation || 0,
            error: result.errors?.virustotal_domain || '',
        },
        vtDomain: {
            malicious: vt.malicious || 0,
            suspicious: vt.suspicious || 0,
            harmless: vt.harmless || 0,
            undetected: vt.undetected || 0,
            reputation: vt.reputation || 0,
            suggestedThreatLabel: vt.suggestedThreatLabel || '',
            registrar: vt.registrar || '',
            categories: stringArray(vt.categories),
            aRecords: stringArray(vt.aRecords),
            creationDate: vt.creationDate || '',
            error: result.errors?.virustotal_domain || '',
        },
        threatfox: tf ? {
            queryStatus: tf.queryStatus || 'ok',
            threatType: tf.threatType || '',
            malware: tf.malware || '',
            malwareAlias: tf.malwareAlias || '',
            confidenceLevel: tf.confidenceLevel || 0,
            firstSeen: tf.firstSeen || '',
            lastSeen: tf.lastSeen || '',
            reporter: tf.reporter || '',
            tags: stringArray(tf.tags),
        } : (result.errors?.threatfox_domain ? { queryStatus: 'error' } : null),
    };
}

// ─── Derived ──────────────────────────────────────────────────────────────────

export const activeDomainEntry  = computed(() => allDomainResults.value[activeDomainIdx.value] || null);
export const activeDomainResult = computed(() => {
    const raw = activeDomainEntry.value?.result || activeDomainEntry.value || null;
    return adaptGenericDomainResult(raw);
});

export const domainResultLinks = computed(() => {
    const r = activeDomainResult.value;
    if (!r) return {};
    return r.links || {};
});

export const highlightedDomainJSON = computed(() => {
    const raw = activeDomainEntry.value?.result || activeDomainEntry.value || null;
    if (!raw) return '';
    return highlightJSON(JSON.stringify(raw, null, 2));
});

// ─── Domain regex (mirrors iocutil.go) ────────────────────────────────────────

const reDomain = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const reIPv4   = /^(\d{1,3}\.){3}\d{1,3}$/;

export function extractDomains(text) {
    const tokens = text.split(/[\s,;\n\r\t]+/).map(t => t.trim()).filter(Boolean);
    const seen = new Set();
    const result = [];
    for (const t of tokens) {
        const lower = t.toLowerCase();
        if (!seen.has(lower) && reDomain.test(t) && !reIPv4.test(t)) {
            seen.add(lower);
            result.push(lower);
        }
    }
    return result;
}

export function clearDomainBulk(domainInputTextRef) {
    domainInputTextRef.value = '';
    domainBulkCount.value    = 0;
}

// ─── Table ────────────────────────────────────────────────────────────────────

export const DOMAIN_TABLE_COLS = [
    { key: '#',            label: '#',             get: (d, i) => i + 1 },
    { key: 'domain',       label: 'Domain',        get: d => d.domain || d._domain || '—' },
    { key: 'riskLevel',    label: 'Risk',          get: d => d.riskLevel || '—' },
    { key: 'vtMalicious',  label: 'VT Malicious',  get: d => d.vtDomain?.malicious ?? d.virustotal?.malicious ?? '—' },
    { key: 'vtThreat',     label: 'VT Threat',     get: d => d.vtDomain?.suggestedThreatLabel || '—' },
    { key: 'registrar',    label: 'Registrar',     get: d => d.vtDomain?.registrar || '—' },
    { key: 'tfMalware',    label: 'TF Malware',    get: d => d.threatfox?.malware || '—' },
    { key: 'link_vt',      label: 'VT Link',       get: d => d.links?.virustotal || '' },
    { key: 'link_tf',      label: 'TF Link',       get: d => d.links?.threatfox || '' },
];

export const visibleDomainTableCols = computed(() =>
    DOMAIN_TABLE_COLS.filter(c => c.key !== 'registrar' || true)
);

export const sortedDomainRows = computed(() => {
    const rows = allDomainResults.value.map((e, i) => ({
        ...adaptGenericDomainResult(e.result || e),
        _idx: i,
        _domain: e.domain || adaptGenericDomainResult(e.result || e)?.domain,
    }));
    const col = DOMAIN_TABLE_COLS.find(c => c.key === domainSortCol.value);
    if (col) {
        rows.sort((a, b) => {
            let va = col.get(a, a._idx);
            let vb = col.get(b, b._idx);
            if (va === '—') va = '';
            if (vb === '—') vb = '';
            return (va < vb ? -1 : va > vb ? 1 : 0) * (domainSortAsc.value ? 1 : -1);
        });
    }
    return rows;
});

export function sortDomainTable(key) {
    if (domainSortCol.value === key) { domainSortAsc.value = !domainSortAsc.value; }
    else { domainSortCol.value = key; domainSortAsc.value = true; }
}

export function renderDomainTableCell(col, row) {
    const val = col.get(row, row._idx);
    if (col.key === '#') return String(row._idx + 1);
    if (col.key === 'domain') return `<span style="font-family:var(--mono);font-size:0.72rem">${val}</span>`;
    if (col.key === 'riskLevel') {
        const r = val === '—' ? 'CLEAN' : val;
        return `<span class="t-risk risk-${r}">${r}</span>`;
    }
    if (col.key === 'vtMalicious' && typeof val === 'number') {
        const c = val >= 5 ? '#f87171' : val >= 1 ? '#fb923c' : '#34d399';
        return `<span style="color:${c};font-weight:600">${val}</span>`;
    }
    if (col.key === 'link_vt') {
        if (!val) return `<span class="t-na">—</span>`;
        return `<a href="${val}" target="_blank" rel="noopener" class="tbl-link-chip">↗ VT</a>`;
    }
    if (col.key === 'link_tf') {
        if (!val) return `<span class="t-na">—</span>`;
        return `<a href="${val}" target="_blank" rel="noopener" class="tbl-link-chip ab">↗ TF</a>`;
    }
    if (val === '—' || val == null || val === '') return `<span class="t-na">—</span>`;
    const display = String(val).length > 55 ? String(val).slice(0, 53) + '…' : String(val);
    return `<span title="${String(val).replace(/"/g, '&quot;')}">${display}</span>`;
}

// ─── Export / copy ────────────────────────────────────────────────────────────

export function copyDomainJSON(activeResultVal) {
    if (!activeResultVal) return;
    navigator.clipboard.writeText(JSON.stringify(activeResultVal, null, 2));
}

export function exportDomainCSV() {
    const rows = allDomainResults.value
        .filter(e => e.result)
        .map(e => adaptGenericDomainResult(e.result || e));
    if (!rows.length) return;
    const cols   = DOMAIN_TABLE_COLS.filter(c => c.key !== '#');
    const header = cols.map(c => c.label).join(',');
    const lines  = rows.map((row, i) => cols.map(c => {
        let v = c.get(row, i);
        if (v == null || v === '—') v = '';
        return '"' + String(v).replace(/"/g, '""') + '"';
    }).join(','));
    _download([header, ...lines].join('\n'), 'iocscan_domain_results.csv', 'text/csv');
}

export function exportDomainJSON() {
    const rows = allDomainResults.value.filter(e => e.result).map(e => e.result || e);
    if (!rows.length) return;
    _download(JSON.stringify(rows, null, 2), 'iocscan_domain_results.json', 'application/json');
}

function _download(content, filename, type) {
    const blob = new Blob([content], { type });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
}
