// composables/useIOCScan.js
// ─────────────────────────────────────────────────────────────────────────────
// Central orchestrator. Re-exports everything so IOCScanner.js import is unchanged.
// Uses Vue 3 GLOBAL build (window.Vue) — no bundler required.
// ─────────────────────────────────────────────────────────────────────────────

// ── Namespace imports for functions we wrap (avoids redeclaration errors) ─────
import * as IPResults   from './useIPResults.js';
import * as HashResults from './useHashResults.js';

import {
    colVisible, fieldVisible,
    hashDynCols, hashColVisible,
    HASH_SECTION_DEFS,
    buildHashDynCols,
    toggleCol, toggleSection, toggleField,
    toggleHashCol, toggleHashSection, setAllCols,
    makeColBadge, makeIpDrawerSections, makeHashDrawerSections,
    HASH_COL_LABELS, HASH_COL_ORDER, HASH_COL_HIDDEN_DEFAULT,
} from './useColumnVisibility.js';

import {
    scanHist,
    addHist, clearHistory, reScan,
    registerReScan,
} from './useScanHistory.js';

const { ref, reactive, computed, watch, nextTick } = Vue;

// ─── Core state ───────────────────────────────────────────────────────────────

export const keys          = reactive({ vt: '', abuse: '', ipapi: '', abusech: '' });
export const ipInputText   = ref('');
export const hashInputText = ref('');
export const ipUseCache    = ref(true);
export const hashUseCache  = ref(true);

export const currentIOCMode = ref('ip');
export const currentView    = ref('cards');
export const hashView       = ref('cards');

export const isIPLoading    = ref(false);
export const isHashLoading  = ref(false);

export const histDrawerOpen   = ref(false);
export const colDrawerOpen    = ref(false);
export const copyMenuOpen     = ref(false);
export const hashCopyMenuOpen = ref(false);

// ─── Computed ─────────────────────────────────────────────────────────────────

export const wideShell = computed(() =>
    (currentView.value === 'table' && currentIOCMode.value === 'ip') ||
    (hashView.value    === 'table' && currentIOCMode.value === 'hash')
);

export const colBadge = computed(() => makeColBadge(currentIOCMode.value));

export const ipDrawerSections = computed(() =>
    makeIpDrawerSections(IPResults.allResults.value, IPResults.activeIdx.value)
);

export const hashDrawerSections = computed(() => {
    void hashDynCols.length;
    return makeHashDrawerSections();
});

// ─── Re-exports from sub-composables (keeps IOCScanner.js import unchanged) ──

export {
    // column visibility
    colVisible, fieldVisible,
    hashDynCols, hashColVisible,
    HASH_SECTION_DEFS,
    HASH_COL_LABELS, HASH_COL_ORDER, HASH_COL_HIDDEN_DEFAULT,
    buildHashDynCols,
    toggleCol, toggleSection, toggleField,
    toggleHashCol, toggleHashSection, setAllCols,

    // history
    scanHist, addHist, clearHistory, reScan,
};

// IP results — re-exported individually (no aliased imports = no conflicts)
export const allResults        = IPResults.allResults;
export const activeIdx         = IPResults.activeIdx;
export const tableSortCol      = IPResults.tableSortCol;
export const tableSortAsc      = IPResults.tableSortAsc;
export const ipError           = IPResults.ipError;
export const isDragging        = IPResults.isDragging;
export const ipBulkCount       = IPResults.ipBulkCount;
export const activeResultEntry = IPResults.activeResultEntry;
export const activeResultIP    = IPResults.activeResultIP;
export const activeResult      = IPResults.activeResult;
export const networkRows       = IPResults.networkRows;
export const highlightedJSON   = IPResults.highlightedJSON;
export const TABLE_COLS        = IPResults.TABLE_COLS;
export const isColVisible      = IPResults.isColVisible;
export const visibleTableCols  = IPResults.visibleTableCols;
export const sortedTableRows   = IPResults.sortedTableRows;
export const sortTable         = IPResults.sortTable;
export const renderTableCell   = IPResults.renderTableCell;
export const extractIPs        = IPResults.extractIPs;
export const copyJSON          = IPResults.copyJSON;
export const exportCSV         = IPResults.exportCSV;
export const exportJSON        = IPResults.exportJSON;
export const abuseColor        = IPResults.abuseColor;
export const yn                = IPResults.yn;

// Hash results — re-exported individually
export const allHashResults    = HashResults.allHashResults;
export const activeHashIdx     = HashResults.activeHashIdx;
export const hashSortCol       = HashResults.hashSortCol;
export const hashSortAsc       = HashResults.hashSortAsc;
export const hashError         = HashResults.hashError;
export const hashBulkCount     = HashResults.hashBulkCount;
export const activeHashEntry   = HashResults.activeHashEntry;
export const activeHashResult  = HashResults.activeHashResult;
export const hashResultLinks   = HashResults.hashResultLinks;
export const signerDetailObj   = HashResults.signerDetailObj;
export const signerIsRevoked   = HashResults.signerIsRevoked;
export const signerIsInvalid   = HashResults.signerIsInvalid;
export const vtNotFound        = HashResults.vtNotFound;
export const highlightedHashJSON   = HashResults.highlightedHashJSON;
export const visibleHashTableCols  = HashResults.visibleHashTableCols;
export const sortedHashRows        = HashResults.sortedHashRows;
export const sortHashTable         = HashResults.sortHashTable;
export const getHashCellVal        = HashResults.getHashCellVal;
export const renderHashTableCell   = HashResults.renderHashTableCell;
export const extractHashes         = HashResults.extractHashes;
export const copyHashJSON          = HashResults.copyHashJSON;
export const exportHashCSV         = HashResults.exportHashCSV;
export const exportHashJSON        = HashResults.exportHashJSON;

// ─── Wrappers (call sub-composable functions, need refs from this file) ───────

export function clearIPBulk()             { IPResults.clearIPBulk(ipInputText); }
export function clearHashBulk()           { HashResults.clearHashBulk(hashInputText); }
export function copyClipboard(format)     { return IPResults.copyClipboard(format, copyMenuOpen); }
export function copyHashClipboard(format) { return HashResults.copyHashClipboard(format, hashCopyMenuOpen); }

// ─── File upload handlers (need ipInputText/hashInputText from this file) ─────

export function handleIPFileUpload(event) {
    const file = event.target.files[0]; if (!file) return;
    event.target.value = '';
    const reader = new FileReader();
    reader.onload = e => {
        const ips = IPResults.extractIPs(e.target.result);
        if (!ips.length) { IPResults.ipError.value = 'No valid IP addresses found in file.'; return; }
        ipInputText.value = ips.join('\n');
        IPResults.ipBulkCount.value = ips.length;
    };
    reader.readAsText(file);
}

export function handleIPDrop(e) {
    IPResults.isDragging.value = false;
    const file = e.dataTransfer.files[0]; if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => {
        const ips = IPResults.extractIPs(ev.target.result);
        if (!ips.length) { IPResults.ipError.value = 'No valid IPs found.'; return; }
        ipInputText.value = ips.join('\n');
        IPResults.ipBulkCount.value = ips.length;
    };
    reader.readAsText(file);
}

export function handleHashFileUpload(event) {
    const file = event.target.files[0]; if (!file) return;
    event.target.value = '';
    const reader = new FileReader();
    reader.onload = e => {
        const hashes = HashResults.extractHashes(e.target.result);
        if (!hashes.length) { HashResults.hashError.value = 'No valid hashes found in file.'; return; }
        hashInputText.value = hashes.join('\n');
        HashResults.hashBulkCount.value = hashes.length;
    };
    reader.readAsText(file);
}

// ─── Drawer controls ──────────────────────────────────────────────────────────

export function openColDrawer()      { colDrawerOpen.value = true;  histDrawerOpen.value = false; }
export function closeColDrawer()     { colDrawerOpen.value = false; }
export function toggleHistDrawer()   { histDrawerOpen.value = !histDrawerOpen.value; colDrawerOpen.value = false; }
export function toggleCopyMenu()     { copyMenuOpen.value     = !copyMenuOpen.value; }
export function toggleHashCopyMenu() { hashCopyMenuOpen.value = !hashCopyMenuOpen.value; }

// ─── Mode / view ──────────────────────────────────────────────────────────────

export function switchIOCMode(mode) { currentIOCMode.value = mode; colDrawerOpen.value = false; histDrawerOpen.value = false; }
export function setView(mode)       { currentView.value = mode; }
export function setHashView(mode)   { hashView.value    = mode; }

// ─── Tab switching ────────────────────────────────────────────────────────────

export function switchTab(i)      { IPResults.activeIdx.value = i; }
export function switchToCard(idx) { IPResults.activeIdx.value = idx; setView('cards'); }

const RISK_DOT_COLOR = { CRITICAL: '#f87171', HIGH: '#fb923c', MEDIUM: '#fbbf24', LOW: '#94a3b8', CLEAN: '#34d399' };
export function riskDotColor(risk) { return RISK_DOT_COLOR[risk] || '#2e4060'; }

// ─── Utility helpers ──────────────────────────────────────────────────────────

export function formatBytes(b) {
    if (!b) return '—';
    if (b < 1024)    return b + ' B';
    if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
    return (b / 1048576).toFixed(2) + ' MB';
}

export function toArr(v) {
    if (!v) return [];
    if (Array.isArray(v)) return v;
    if (typeof v === 'string' && v.trim()) return [v];
    return [];
}

export function vtStatPart(idx) {
    const d = IPResults.activeResult.value;
    if (!d || !d.virustotal) return '—';
    const vt = d.virustotal;
    return [vt.suspicious ?? 0, vt.undetected ?? 0, vt.harmless ?? 0][idx] ?? '—';
}

// ─── API calls ────────────────────────────────────────────────────────────────

export async function doIPScan() {
    const ip = ipInputText.value.trim();
    if (!ip) { IPResults.ipError.value = 'Enter at least one IP address.'; return; }
    IPResults.ipError.value = '';
    isIPLoading.value = true;
    try {
        const res = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ip,
                vt_key: keys.vt, abuse_key: keys.abuse,
                ipapi_key: keys.ipapi, abusech_key: keys.abusech,
                use_cache: ipUseCache.value,
            }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
        IPResults.allResults.value = data;
        IPResults.activeIdx.value  = 0;
        data.forEach(e => { if (e.result) addHist(e.ip, e.result.riskLevel || 'CLEAN'); });
        if (currentView.value === 'table') IPResults.tableSortCol.value = '#';
        nextTick(() => { document.getElementById('cardsView')?.scrollIntoView({ behavior: 'smooth', block: 'start' }); });
    } catch (e) {
        IPResults.ipError.value = `Scan failed: ${e.message}`;
    } finally {
        isIPLoading.value = false;
    }
}

export async function doHashScanAction() {
    const raw = hashInputText.value.trim();
    if (!raw) { HashResults.hashError.value = 'Please enter at least one hash.'; return; }
    const hashes = HashResults.extractHashes(raw);
    if (!hashes.length) { HashResults.hashError.value = 'No valid MD5/SHA1/SHA256 hashes found.'; return; }
    HashResults.hashError.value = '';
    isHashLoading.value = true;
    try {
        const resp = await fetch('/api/scan/hash', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hashes, vt_key: keys.vt, abusech_key: keys.abusech, use_cache: hashUseCache.value }),
        });
        if (!resp.ok) { const t = await resp.text(); throw new Error(t || resp.statusText); }
        const data = await resp.json();
        HashResults.allHashResults.value = data;
        HashResults.activeHashIdx.value  = 0;
        buildHashDynCols(data);
        data.forEach(e => {
            const r = e.result || e;
            addHist(e.hash || r.virustotal?.sha256 || r.virustotal?.md5 || '?', r.riskLevel || (e.error ? 'ERROR' : 'UNKNOWN'));
        });
    } catch (err) {
        HashResults.hashError.value = 'Hash scan error: ' + err.message;
    } finally {
        isHashLoading.value = false;
    }
}

// ─── Register reScan + reactive watches ──────────────────────────────────────

registerReScan(ioc => { ipInputText.value = ioc; doIPScan(); });

watch(ipInputText,   v => { IPResults.ipBulkCount.value   = v.trim() ? IPResults.extractIPs(v).length   : 0; });
watch(hashInputText, v => { HashResults.hashBulkCount.value = v.trim() ? HashResults.extractHashes(v).length : 0; });