// composables/useIPResults.js
// ─────────────────────────────────────────────────────────────────────────────
// All state, computed properties, table config, cell rendering, export/copy,
// and file-upload logic specific to IP scan results.
// Uses Vue 3 GLOBAL build (window.Vue) — no bundler required.
// ─────────────────────────────────────────────────────────────────────────────

import {
    colVisible, fieldVisible,
} from './useColumnVisibility.js';

import { highlightJSON } from '../utils.js';

const { ref, computed } = Vue;

// ─── State ────────────────────────────────────────────────────────────────────

export const allResults  = ref([]);
export const activeIdx   = ref(0);
export const tableSortCol = ref('#');
export const tableSortAsc = ref(true);
export const ipError      = ref('');
export const isDragging   = ref(false);
export const ipBulkCount  = ref(0);

// ─── Derived ──────────────────────────────────────────────────────────────────

export const activeResultEntry = computed(() => allResults.value[activeIdx.value] || null);
export const activeResult      = computed(() => activeResultEntry.value?.result || activeResultEntry.value || null);
export const activeResultIP    = computed(() =>
    activeResultEntry.value?.ip ||
    activeResult.value?.ipAddress ||
    activeResult.value?.ip ||
    ''
);

export const networkRows = computed(() => {
    const d = activeResult.value;
    if (!d) return [];
    const g = d.geo || {};
    return [
        ['IP',          d.ipAddress || d.ip,                                  'net-ip'],
        ['ISP',         g.isp || g.asn_org || '—',                            'net-isp'],
        ['Country',     g.country || g.countryCode || '—',                    'net-country'],
        ['City',        g.city || '—',                                        'net-city'],
        ['Timezone',    g.timezone || '—',                                    'net-tz'],
        // Public, Whitelisted, Hostnames moved to AbuseIPDB card — they come from that API
    ].filter(([, v]) => v && v !== '—');
});

export const highlightedJSON = computed(() => {
    if (!activeResult.value) return '';
    return highlightJSON(JSON.stringify(activeResult.value, null, 2));
});

// ─── Table columns ────────────────────────────────────────────────────────────

export const TABLE_COLS = [
    { key: '#',                    label: '#',              vis: null,                  get: (d, i) => i + 1 },
    { key: 'ipAddress',            label: 'IP Address',     vis: null,                  get: d => d.ipAddress || d.ip || '—' },
    { key: 'riskLevel',            label: 'Risk',           vis: 'risk',                get: d => d.riskLevel || '—' },
    { key: 'isp',                  label: 'ISP',            vis: 'field:net-isp',       get: d => d.geo?.isp || '—' },
    { key: 'country',              label: 'Country',        vis: 'field:net-country',   get: d => d.geo?.country || d.geo?.countryCode || '—' },
    { key: 'city',                 label: 'City',           vis: 'field:net-city',      get: d => d.geo?.city || '—' },
    { key: 'timezone',             label: 'Timezone',       vis: 'field:net-tz',        get: d => d.geo?.timezone || '—' },
    { key: 'isPublic',             label: 'Public',         vis: 'field:net-public',    get: d => d.abuseipdb?.isPublic },
    { key: 'isWhitelisted',        label: 'Whitelisted',    vis: 'field:net-wl',        get: d => d.abuseipdb?.isWhitelisted },
    { key: 'hostnames',            label: 'Hostnames',      vis: 'field:net-hostnames', get: d => d.abuseipdb?.hostnames || [] },
    { key: 'abuseConfidenceScore', label: 'Abuse %',        vis: 'field:ab-score',      get: d => d.abuseipdb?.confidenceScore ?? '—' },
    { key: 'totalReports',         label: 'Reports',        vis: 'field:ab-reports',    get: d => d.abuseipdb?.totalReports ?? '—' },
    { key: 'lastReportedAt',       label: 'Last Reported',  vis: 'field:ab-lastreport', get: d => d.abuseipdb?.lastReportedAt ? d.abuseipdb.lastReportedAt.replace('T', ' ').replace('+00:00', '') : '—' },
    { key: 'vtStats_S_U_H',        label: 'VT S/U/H',       vis: 'field:vt-summary',    get: d => d.virustotal ? `${d.virustotal.suspicious}/${d.virustotal.undetected}/${d.virustotal.harmless}` : '—' },
    { key: 'vtMalicious',          label: 'VT Malicious',   vis: 'field:vt-malicious',  get: d => d.virustotal?.malicious ?? '—' },
    { key: 'vtSuspicious',         label: 'VT Suspicious',  vis: 'field:vt-suspicious', get: d => d.virustotal?.suspicious ?? '—' },
    { key: 'vtReputation',         label: 'VT Reputation',  vis: 'vt',                  get: d => d.virustotal?.reputation ?? '—' },
    { key: 'link_virustotal',      label: 'VT Link',        vis: 'field:link-vt',       get: d => d.links?.virustotal || '' },
    { key: 'link_abuseipdb',       label: 'AbuseIPDB Link', vis: 'field:link-abuse',    get: d => d.links?.abuseipdb || '' },
    { key: 'link_ipapi',           label: 'IPAPI Link',     vis: 'field:link-ipapi',    get: d => d.links?.ipapi || '' },
];

export function isColVisible(col) {
    if (!col.vis) return true;
    if (col.vis.startsWith('field:')) return fieldVisible[col.vis.slice(6)] !== false;
    return colVisible[col.vis] !== false;
}

export const visibleTableCols = computed(() => TABLE_COLS.filter(c => isColVisible(c)));

export const sortedTableRows = computed(() => {
    const rows = allResults.value
        .map((e, i) => ({ ...(e.result || e), _ip: e.ip || e.ipAddress || e.ip, _idx: i }))
        .filter(e => !!(e.ipAddress || e.ip || e._ip));
    const col = TABLE_COLS.find(c => c.key === tableSortCol.value);
    if (col) rows.sort((a, b) => {
        let va = col.get(a, a._idx), vb = col.get(b, b._idx);
        if (typeof va === 'boolean') va = va ? 1 : 0;
        if (typeof vb === 'boolean') vb = vb ? 1 : 0;
        if (Array.isArray(va)) va = va.length;
        if (Array.isArray(vb)) vb = vb.length;
        return (va < vb ? -1 : va > vb ? 1 : 0) * (tableSortAsc.value ? 1 : -1);
    });
    return rows;
});

export function sortTable(key) {
    if (tableSortCol.value === key) { tableSortAsc.value = !tableSortAsc.value; }
    else { tableSortCol.value = key; tableSortAsc.value = true; }
}

export function renderTableCell(col, row, i) {
    const val = col.get(row, i);
    if (col.key === 'riskLevel') {
        const risk = val || 'CLEAN';
        return `<span class="t-risk risk-${risk}">${risk}</span>`;
    }
    if (col.key === 'isPublic' || col.key === 'isWhitelisted') {
        if (val == null) return `<span class="t-na">—</span>`;
        return val ? `<span class="t-bool-yes">✓ Yes</span>` : `<span class="t-bool-no">✗ No</span>`;
    }
    if (col.key === 'hostnames') {
        if (!val || !val.length) return `<span class="t-na">—</span>`;
        return val.map(h => `<span class="t-hostname">${h}</span>`).join('');
    }
    if (col.key === 'abuseConfidenceScore' && typeof val === 'number') {
        return `<span style="color:${abuseColor(val)};font-weight:600">${val}%</span>`;
    }
    if (col.key === 'vtMalicious' && typeof val === 'number') {
        const c = val >= 5 ? '#f87171' : val >= 1 ? '#fb923c' : '#34d399';
        return `<span style="color:${c};font-weight:600">${val}</span>`;
    }
    if (col.key === 'vtReputation' && typeof val === 'number') {
        const c = val > 0 ? '#34d399' : val < 0 ? '#f87171' : '#4d6480';
        return `<span style="color:${c}">${val}</span>`;
    }
    if (col.key === 'link_virustotal') {
        if (!val) return `<span class="t-na">—</span>`;
        return `<a href="${encodeURI(val)}" target="_blank" rel="noopener" class="tbl-link-chip">↗ VT</a>`;
    }
    if (col.key === 'link_abuseipdb') {
        if (!val) return `<span class="t-na">—</span>`;
        return `<a href="${encodeURI(val)}" target="_blank" rel="noopener" class="tbl-link-chip ab">↗ AbuseIPDB</a>`;
    }
    if (col.key === 'link_ipapi') {
        if (!val) return `<span class="t-na">—</span>`;
        return `<a href="${encodeURI(val)}" target="_blank" rel="noopener" class="tbl-link-chip ip">↗ IPAPI</a>`;
    }
    if (val === '—' || val == null) return `<span class="t-na">—</span>`;
    return String(val);
}

// ─── IOC extraction ───────────────────────────────────────────────────────────

export function extractIPs(text) {
    const ipv4 = /\b(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\b/g;
    const ipv6 = /\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g;
    const found = [...(text.match(ipv4) || []), ...(text.match(ipv6) || [])];
    return [...new Map(found.map(ip => [ip, ip])).values()];
}

export function clearIPBulk(ipInputTextRef) {
    ipInputTextRef.value = '';
    ipBulkCount.value    = 0;
}

// ─── Export / copy ────────────────────────────────────────────────────────────

export function copyJSON(activeResultVal) {
    if (!activeResultVal) return;
    navigator.clipboard.writeText(JSON.stringify(activeResultVal, null, 2));
}

export async function copyClipboard(format, copyMenuOpenRef) {
    copyMenuOpenRef.value = false;
    const rows = allResults.value.map(e => e.result || e).filter(e => !!e);
    if (!rows.length) return;
    let text = '';
    if (format === 'json') {
        text = JSON.stringify(_buildFilteredRows(), null, 2);
    } else if (format === 'csv') {
        const cols   = TABLE_COLS.filter(c => c.key !== '#' && isColVisible(c));
        const header = cols.map(c => c.label).join(',');
        const lines  = rows.map(row => cols.map(c => {
            let v = c.get(row);
            if (Array.isArray(v)) v = v.join('; ');
            if (typeof v === 'boolean') v = v ? 'true' : 'false';
            if (v == null || v === '—') v = '';
            return '"' + String(v).replace(/"/g, '""') + '"';
        }).join(','));
        text = [header, ...lines].join('\n');
    } else if (format === 'ips') {
        text = rows.map(r => r.ipAddress || r.ip).filter(Boolean).join('\n');
    }
    try {
        await navigator.clipboard.writeText(text);
    } catch (e) {
        _fallbackCopy(text);
    }
}

export function exportCSV() {
    const rows = allResults.value.map(e => e.result || e).filter(e => !!e);
    if (!rows.length) return;
    const cols   = TABLE_COLS.filter(c => c.key !== '#' && isColVisible(c));
    const header = cols.map(c => c.label).join(',');
    const lines  = rows.map(row => cols.map(c => {
        let v = c.get(row);
        if (Array.isArray(v)) v = v.join('; ');
        if (typeof v === 'boolean') v = v ? 'true' : 'false';
        if (v == null || v === '—') v = '';
        return '"' + String(v).replace(/"/g, '""') + '"';
    }).join(','));
    _download([header, ...lines].join('\n'), 'iocscan_results.csv', 'text/csv');
}

export function exportJSON() {
    const data = _buildFilteredRows();
    if (!data.length) return;
    _download(JSON.stringify(data, null, 2), 'iocscan_results.json', 'application/json');
}

// ─── Private helpers ──────────────────────────────────────────────────────────

function _buildFilteredRows() {
    const cols = TABLE_COLS.filter(c => c.key !== '#' && isColVisible(c));
    return allResults.value.map((e, i) => ({ row: e.result || e, idx: i }))
        .filter(({ row }) => !!row)
        .map(({ row, idx }) => {
        const obj = {};
        cols.forEach(c => {
            let v = c.get(row, idx);
            if (v === '—') v = null;
            if (typeof v === 'boolean') v = v ? true : false;
            if (Array.isArray(v)) v = v.join('; ');
            const exportKey = c.key === 'link_virustotal' ? 'virustotal_link'
                : c.key === 'link_abuseipdb'              ? 'abuseipdb_link'
                    : c.key === 'link_ipapi'                  ? 'ipapi_link'
                        : c.key;
            obj[exportKey] = v || null;
        });
        return obj;
    });
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

// ─── Utility helpers (IP-specific) ───────────────────────────────────────────

export function abuseColor(s) { return s >= 75 ? '#f87171' : s >= 40 ? '#fb923c' : s > 0 ? '#fbbf24' : '#34d399'; }
export function yn(b)         { return b ? '✓ Yes' : '✗ No'; }
