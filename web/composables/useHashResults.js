// composables/useHashResults.js
// ─────────────────────────────────────────────────────────────────────────────
// All state, computed properties, table config, cell rendering, export/copy,
// and file-upload logic specific to hash scan results.
// Uses Vue 3 GLOBAL build (window.Vue) — no bundler required.
// ─────────────────────────────────────────────────────────────────────────────

import {
    hashDynCols,
} from './useColumnVisibility.js';

import { highlightJSON } from '../utils.js';

const { ref, computed } = Vue;

// ─── State ────────────────────────────────────────────────────────────────────

export const allHashResults = ref([]);
export const activeHashIdx  = ref(0);
export const hashSortCol    = ref('#');
export const hashSortAsc    = ref(true);
export const hashError      = ref('');
export const hashBulkCount  = ref(0);

function isGenericHashResult(result) {
    return !!(result && typeof result === 'object' && result.ioc && result.iocType === 'hash' && result.results);
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
            status: result.errors?.[name] ? 'error' : (fields.queryStatus || 'ok'),
            error: result.errors?.[name] || '',
        };
    }
    return out;
}

function adaptGenericHashResult(result) {
    if (!isGenericHashResult(result)) return result;

    const vt = result.results?.virustotal_hash || {};
    const mb = result.results?.malwarebazaar || {};
    const tf = result.results?.threatfox_hash || null;
    const sha256 = vt.sha256 || result.ioc;

    return {
        hash: result.ioc,
        hashType: result.ioc.length === 32 ? 'MD5' : result.ioc.length === 40 ? 'SHA1' : result.ioc.length === 64 ? 'SHA256' : 'unknown',
        riskLevel: result.riskLevel,
        cached: cachedAll(result),
        cacheHits: result.cacheHits || null,
        diagnostics: diagnosticsFromGeneric(result),
        links: {
            virustotal: `https://www.virustotal.com/gui/file/${sha256}`,
            malwarebazaar: `https://bazaar.abuse.ch/sample/${sha256}`,
        },
        virustotal: {
            md5: vt.md5 || '',
            sha1: vt.sha1 || '',
            sha256: vt.sha256 || '',
            meaningfulName: vt.meaningfulName || '',
            magic: vt.magic || '',
            magika: vt.magika || '',
            malicious: vt.malicious || 0,
            suspicious: vt.suspicious || 0,
            harmless: vt.harmless || 0,
            undetected: vt.undetected || 0,
            reputation: vt.reputation || 0,
            suggestedThreatLabel: vt.suggestedThreatLabel || '',
            popularThreatNames: stringArray(vt.popularThreatNames),
            popularThreatCategories: stringArray(vt.popularThreatCategories),
            sandboxMalwareClassifications: stringArray(vt.sandboxMalwareClassifications),
            sigmaAnalysisSummary: vt.sigmaAnalysisSummary || null,
            signatureSigners: vt.signatureSigners || '',
            signerDetail: vt.signerStatus ? {
                status: vt.signerStatus || '',
                name: vt.signerName || '',
                certIssuer: vt.signerCertIssuer || '',
                validFrom: vt.signerValidFrom || '',
                validTo: vt.signerValidTo || '',
            } : null,
            error: result.errors?.virustotal_hash || '',
        },
        malwarebazaar: {
            queryStatus: mb.queryStatus || (result.errors?.malwarebazaar ? 'error' : 'no_results'),
            fileName: mb.fileName || '',
            fileType: mb.fileType || '',
            signature: mb.signature || '',
            tags: stringArray(mb.tags),
            comment: mb.comment || '',
        },
        threatfox: tf ? {
            queryStatus: tf.queryStatus || 'ok',
            iocs: tf.queryStatus === 'ok' ? [{
                malware: tf.malware || '',
                threatType: tf.threatType || '',
                confidenceLevel: tf.confidenceLevel || 0,
                firstSeen: tf.firstSeen || '',
                tags: stringArray(tf.tags),
            }] : [],
        } : (result.errors?.threatfox_hash ? { queryStatus: 'error', iocs: [] } : null),
    };
}

export function adaptHashEntries(entries) {
    return (entries || []).map(entry => ({
        hash: entry.hash || entry.ioc,
        result: adaptGenericHashResult(entry.result || entry),
        error: entry.error || '',
    }));
}

// ─── Derived ──────────────────────────────────────────────────────────────────

export const activeHashEntry  = computed(() => allHashResults.value[activeHashIdx.value] || null);
export const activeHashResult = computed(() => {
    const raw = activeHashEntry.value?.result || activeHashEntry.value || null;
    return adaptGenericHashResult(raw);
});

export const hashResultLinks = computed(() => {
    const r = activeHashResult.value;
    if (!r) return {};
    if (r.links && typeof r.links === 'object') return r.links;
    return {};
});

export const signerDetailObj = computed(() => {
    const d = activeHashResult.value?.virustotal?.signerDetail;
    if (!d || typeof d !== 'object') return null;
    return d;
});

export const signerIsRevoked = computed(() => {
    const s = signerDetailObj.value?.status || '';
    return /revoked/i.test(s);
});

export const signerIsInvalid = computed(() => {
    const s = signerDetailObj.value?.status || '';
    if (!s) return false;
    if (signerIsRevoked.value) return false;
    if (/valid/i.test(s) && !/invalid/i.test(s)) return false;
    return /(invalid|expired|untrusted|mismatch|error|fail)/i.test(s);
});

export const signerIsValid = computed(() => {
    const s = signerDetailObj.value?.status || '';
    if (!s) return false;
    if (signerIsRevoked.value || signerIsInvalid.value) return false;
    return /valid/i.test(s);
});

export const vtNotFound = computed(() => {
    const r = activeHashResult.value;
    if (!r) return false;
    const vt = r.virustotal;
    if (!vt) return true;
    const allZero = (vt.malicious === 0 && vt.suspicious === 0 &&
        vt.harmless === 0 && vt.undetected === 0);
    const noMeta = !vt.meaningfulName && !vt.magic && !vt.magika && !vt.suggestedThreatLabel;
    return allZero && noMeta;
});

export const highlightedHashJSON = computed(() => {
    const raw = activeHashEntry.value?.result || activeHashEntry.value || null;
    if (!raw) return '';
    return highlightJSON(JSON.stringify(raw, null, 2));
});

// ─── Table ────────────────────────────────────────────────────────────────────

export const visibleHashTableCols = computed(() => {
    const base = [{ key: '#', label: '#' }, { key: 'hash', label: 'Hash' }];
    const dyn  = hashDynCols.filter(c => c.visible).map(c => ({ key: c.key, label: c.label }));
    return [...base, ...dyn];
});

export const sortedHashRows = computed(() => {
    const rows = allHashResults.value.map((e, i) => ({ ...adaptGenericHashResult(e.result || e), _idx: i, _hash: e.hash || e.ioc }));
    rows.sort((a, b) => {
        const va = getHashCellVal(a, hashSortCol.value);
        const vb = getHashCellVal(b, hashSortCol.value);
        return (va < vb ? -1 : va > vb ? 1 : 0) * (hashSortAsc.value ? 1 : -1);
    });
    return rows;
});

export function sortHashTable(key) {
    if (hashSortCol.value === key) hashSortAsc.value = !hashSortAsc.value;
    else { hashSortCol.value = key; hashSortAsc.value = true; }
}

export function getHashCellVal(d, key) {
    if (key === '#') return d._idx;
    if (key === 'hash') return d._hash || d.virustotal?.sha256 || d.virustotal?.sha1 || d.virustotal?.md5 || '';
    if (key === 'riskLevel')          return d.riskLevel || '—';
    if (key === 'hashType')           return d.hashType || '—';
    if (key === 'link_virustotal')    return d.links?.virustotal || '—';
    if (key === 'link_malwarebazaar') return d.links?.malwarebazaar || '—';

    const vtMap = {
        vtMalicious: 'malicious', vtSuspicious: 'suspicious', vtHarmless: 'harmless',
        vtUndetected: 'undetected', vtReputation: 'reputation',
        meaningfulName: 'meaningfulName', magic: 'magic', magika: 'magika',
        md5: 'md5', sha1: 'sha1', sha256: 'sha256',
        suggestedThreatLabel: 'suggestedThreatLabel',
        popularThreatCategories: 'popularThreatCategories',
        popularThreatNames: 'popularThreatNames',
        sandboxMalwareClassifications: 'sandboxMalwareClassifications',
        sigmaAnalysisSummary: 'sigmaAnalysisSummary',
        signatureSigners: 'signatureSigners',
        signerDetail: 'signerDetail',
    };
    if (key in vtMap) {
        const v = d.virustotal?.[vtMap[key]];
        if (v == null) return '—';
        if (Array.isArray(v)) return v.join(', ') || '—';
        if (typeof v === 'object') return JSON.stringify(v);
        return String(v);
    }

    const mbMap = {
        mbQueryStatus: 'queryStatus', mbFileName: 'fileName', mbFileType: 'fileType',
        mbSignature: 'signature', mbTags: 'tags', mbComment: 'comment',
    };
    if (key in mbMap) {
        const v = d.malwarebazaar?.[mbMap[key]];
        if (v == null) return '—';
        if (Array.isArray(v)) return v.join(', ') || '—';
        return String(v);
    }

    const v = d[key];
    if (v == null) return '—';
    if (Array.isArray(v)) return v.join(', ') || '—';
    if (typeof v === 'object') return JSON.stringify(v);
    return String(v);
}

export function renderHashTableCell(col, row) {
    if (col.key === '#') return String(row._idx + 1);
    if (col.key === 'hash') {
        const h = row._hash || row.virustotal?.sha256 || row.virustotal?.sha1 || row.virustotal?.md5 || '?';
        return `<span style="font-size:0.65rem">${h.slice(0, 16)}…</span>`;
    }
    if (col.key === 'riskLevel') {
        const r = row.riskLevel || 'CLEAN';
        return `<span class="t-risk risk-${r}">${r}</span>`;
    }
    if (col.key === 'mbQueryStatus') {
        const raw   = row.malwarebazaar?.queryStatus;
        const color = raw === 'ok' ? '#34d399' : raw === 'hash_not_found' ? '#4d6480' : '#94a3b8';
        const label = raw === 'ok' ? 'Found' : raw === 'hash_not_found' ? 'Not found' : raw || '—';
        return `<span style="color:${color};font-weight:${raw === 'ok' ? 700 : 400}">${label}</span>`;
    }
    if (col.key === 'link_virustotal') {
        const url = row.links?.virustotal;
        if (!url) return `<span class="t-na">—</span>`;
        const vt = row.virustotal || {};
        const notFound = vt.malicious === 0 && vt.suspicious === 0 && vt.harmless === 0 && vt.undetected === 0 && !vt.meaningfulName;
        return notFound
            ? `<span class="tbl-link-na" title="Not found in VirusTotal">✗ VT</span>`
            : `<a href="${url}" target="_blank" rel="noopener" class="tbl-link-chip">↗ VT</a>`;
    }
    if (col.key === 'link_malwarebazaar') {
        const url = row.links?.malwarebazaar;
        if (!url) return `<span class="t-na">—</span>`;
        const notFound = row.malwarebazaar?.queryStatus && row.malwarebazaar.queryStatus !== 'ok';
        return notFound
            ? `<span class="tbl-link-na" title="Not found in MalwareBazaar">✗ MB</span>`
            : `<a href="${url}" target="_blank" rel="noopener" class="tbl-link-chip ab">↗ MB</a>`;
    }
    const val = getHashCellVal(row, col.key);
    if (val === '—') return `<span class="t-na">—</span>`;
    if (col.key === 'vtMalicious' && typeof val === 'string' && val !== '—') {
        const n = parseInt(val); const c = n >= 5 ? '#f87171' : n >= 1 ? '#fb923c' : '#34d399';
        return `<span style="color:${c};font-weight:600">${val}</span>`;
    }
    if (col.key === 'vtReputation' && typeof val === 'string' && val !== '—') {
        const n = parseInt(val); const c = n > 0 ? '#34d399' : n < 0 ? '#f87171' : '#4d6480';
        return `<span style="color:${c}">${val}</span>`;
    }
    const display = val.length > 60 ? val.slice(0, 58) + '…' : val;
    return `<span title="${val.replace(/"/g, '&quot;')}">${display}</span>`;
}

// ─── IOC extraction ───────────────────────────────────────────────────────────

export function extractHashes(text) {
    const sha256 = /\b[a-fA-F0-9]{64}\b/g;
    const sha1   = /\b[a-fA-F0-9]{40}\b/g;
    const md5    = /\b[a-fA-F0-9]{32}\b/g;
    const found  = [...(text.match(sha256) || []), ...(text.match(sha1) || []), ...(text.match(md5) || [])];
    return [...new Map(found.map(h => [h.toLowerCase(), h.toLowerCase()])).values()];
}

export function clearHashBulk(hashInputTextRef) {
    hashInputTextRef.value = '';
    hashBulkCount.value    = 0;
}

// ─── Export / copy ────────────────────────────────────────────────────────────

export function copyHashJSON(activeHashResultVal) {
    if (!activeHashResultVal) return;
    navigator.clipboard.writeText(JSON.stringify(activeHashResultVal, null, 2));
}

export async function copyHashClipboard(format, hashCopyMenuOpenRef) {
    hashCopyMenuOpenRef.value = false;
    const rows = allHashResults.value.filter(e => e.result).map(e => adaptGenericHashResult(e.result || e));
    if (!rows.length) return;
    let text = '';
    if (format === 'json') {
        text = JSON.stringify(rows.map(_buildHashExportRow), null, 2);
    } else if (format === 'csv') {
        const { header, lines } = _buildHashCSV(rows);
        text = [header, ...lines].join('\n');
    } else if (format === 'hashes') {
        text = rows.map(r => r.virustotal?.sha256 || r.virustotal?.sha1 || r.virustotal?.md5 || r._hash || r.hash).filter(Boolean).join('\n');
    }
    try {
        await navigator.clipboard.writeText(text);
        const btn = document.getElementById('hashClipboardBtn');
        if (btn) { const orig = btn.textContent; btn.textContent = '✓ Copied!'; setTimeout(() => btn.textContent = orig, 2000); }
    } catch (e) {
        _fallbackCopy(text);
    }
}

export function exportHashCSV() {
    const rows = allHashResults.value.filter(e => e.result).map(e => adaptGenericHashResult(e.result || e));
    if (!rows.length) return;
    const { header, lines } = _buildHashCSV(rows);
    _download([header, ...lines].join('\n'), 'iocscan_hash_results.csv', 'text/csv');
}

export function exportHashJSON() {
    const rows = allHashResults.value.filter(e => e.result).map(e => e.result || e);
    if (!rows.length) return;
    _download(JSON.stringify(rows.map(_buildHashExportRow), null, 2), 'iocscan_hash_results.json', 'application/json');
}

// ─── Private helpers ──────────────────────────────────────────────────────────

function _buildHashExportRow(row) {
    const cols = hashDynCols.filter(c => c.visible);
    const obj  = {};
    cols.forEach(c => {
        let v = getHashCellVal(row, c.key);
        if (v === '—') v = null;
        const exportKey = c.key === 'link_virustotal'    ? 'virustotal_link'
            : c.key === 'link_malwarebazaar' ? 'malwarebazaar_link'
                : c.key;
        obj[exportKey] = v;
    });
    return obj;
}

function _buildHashCSV(rows) {
    const cols   = hashDynCols.filter(c => c.visible);
    const header = cols.map(c => c.label).join(',');
    const lines  = rows.map(row => cols.map(c => {
        let v = getHashCellVal(row, c.key);
        if (v == null || v === '—') v = '';
        return '"' + String(v).replace(/"/g, '""') + '"';
    }).join(','));
    return { header, lines };
}

function _download(content, filename, type) {
    const blob = new Blob([content], { type });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename; a.click();
}

function _fallbackCopy(text) {
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.cssText = 'position:fixed;opacity:0';
    document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); document.body.removeChild(ta);
}
