// composables/useIOCScan.js
// ─────────────────────────────────────────────────────────────────────────────
// Central state + logic composable for the IOC scanner.
// Contains: all reactive state, API calls, computed results,
// table columns/sorting/rendering, export/copy, file upload, history.
//
// Uses the Vue 3 GLOBAL build (window.Vue) — no bundler required.
// ─────────────────────────────────────────────────────────────────────────────

import {
    colVisible, fieldVisible,
    hashDynCols, hashColVisible,
    HASH_COL_LABELS, HASH_COL_ORDER, HASH_COL_HIDDEN_DEFAULT, HASH_SECTION_DEFS,
    buildHashDynCols,
    toggleCol, toggleSection, toggleField,
    toggleHashCol, toggleHashSection, setAllCols,
    makeColBadge, makeIpDrawerSections, makeHashDrawerSections,
} from './useColumnVisibility.js';

const { ref, reactive, computed, watch, nextTick } = Vue;

// ─── Core state ───────────────────────────────────────────────────────────────

export const keys         = reactive({ vt:'', abuse:'', ipapi:'', abusech:'' });
export const scanMode     = ref('complex');
export const ipInputText  = ref('');
export const hashInputText= ref('');
export const ipUseCache   = ref(true);
export const hashUseCache = ref(true);
export const isDragging   = ref(false);
export const ipBulkCount  = ref(0);
export const hashBulkCount= ref(0);

export const currentIOCMode = ref('ip');
export const currentView    = ref('cards');
export const hashView       = ref('cards');

export const allResults     = ref([]);
export const activeIdx      = ref(0);
export const allHashResults = ref([]);
export const activeHashIdx  = ref(0);

export const isIPLoading    = ref(false);
export const isHashLoading  = ref(false);
export const ipError        = ref('');
export const hashError      = ref('');

export const scanHist         = reactive([]);
export const histDrawerOpen   = ref(false);
export const colDrawerOpen    = ref(false);
export const copyMenuOpen     = ref(false);
export const hashCopyMenuOpen = ref(false);
export const tableSortCol     = ref('#');
export const tableSortAsc     = ref(true);
export const hashSortCol      = ref('#');
export const hashSortAsc      = ref(true);

// Re-export column state so components only need this one import
export {
    colVisible, fieldVisible,
    hashDynCols, hashColVisible,
    HASH_SECTION_DEFS,
    toggleCol, toggleSection, toggleField,
    toggleHashCol, toggleHashSection, setAllCols,
};

// ─── Computed ─────────────────────────────────────────────────────────────────

export const wideShell = computed(() =>
    (currentView.value === 'table' && currentIOCMode.value === 'ip') ||
    (hashView.value   === 'table' && currentIOCMode.value === 'hash')
);

export const colBadge = computed(() => makeColBadge(currentIOCMode.value));

export const ipDrawerSections = computed(() =>
    makeIpDrawerSections(allResults.value, activeIdx.value)
);

export const hashDrawerSections = computed(() => {
    // Depend on hashDynCols length so Vue re-evaluates after build
    void hashDynCols.length;
    return makeHashDrawerSections();
});

export const activeResultEntry = computed(() => allResults.value[activeIdx.value] || null);
export const activeResultIP    = computed(() => activeResultEntry.value?.ip || '');
export const activeResult      = computed(() => activeResultEntry.value?.result || null);

export const activeHashEntry  = computed(() => allHashResults.value[activeHashIdx.value] || null);
export const activeHashResult = computed(() => activeHashEntry.value?.result || activeHashEntry.value || null);

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
    return s.length > 0 && !signerIsRevoked.value;
});

export const vtNotFound = computed(() => {
    const r = activeHashResult.value;
    if (!r) return false;
    const vt = r.virustotal;
    if (!vt) return true;
    const allZero = (vt.malicious === 0 && vt.suspicious === 0 &&
        vt.harmless  === 0 && vt.undetected === 0);
    const noMeta  = !vt.meaningfulName && !vt.magic && !vt.magika && !vt.suggestedThreatLabel;
    return allZero && noMeta;
});

export const networkRows = computed(() => {
    const d = activeResult.value;
    if (!d) return [];
    const g = d.geo || {};
    return [
        ['IP',          d.ipAddress||d.ip,                               'net-ip'],
        ['ISP',         g.isp||g.asn_org||'—',                          'net-isp'],
        ['Country',     g.country||g.countryCode||'—',                   'net-country'],
        ['City',        g.city||'—',                                     'net-city'],
        ['Timezone',    g.timezone||'—',                                 'net-tz'],
        ['Public',      g.isPublic!=null ? yn(g.isPublic) : '—',        'net-public'],
        ['Whitelisted', g.isWhitelisted!=null ? yn(g.isWhitelisted):'—', 'net-wl'],
        ['Hostnames',   (g.hostnames&&g.hostnames.length)?g.hostnames.join(', '):'—','net-hostnames'],
    ].filter(([,v]) => v && v !== '—');
});

export const highlightedJSON = computed(() => {
    if (!activeResult.value) return '';
    return highlight(JSON.stringify(activeResult.value, null, 2));
});

export const highlightedHashJSON = computed(() => {
    if (!activeHashResult.value) return '';
    return highlight(JSON.stringify(activeHashResult.value, null, 2));
});

// ─── Table: IP mode ───────────────────────────────────────────────────────────

export const TABLE_COLS = [
    { key:'#',                    label:'#',             vis:null,                 get:(d,i)=>i+1 },
    { key:'ipAddress',            label:'IP Address',    vis:null,                 get:d=>d.ipAddress||d.ip||'—' },
    { key:'riskLevel',            label:'Risk',          vis:'risk',               get:d=>d.riskLevel||'—' },
    { key:'isp',                  label:'ISP',           vis:'field:net-isp',      get:d=>d.geo?.isp||'—' },
    { key:'country',              label:'Country',       vis:'field:net-country',  get:d=>d.geo?.country||d.geo?.countryCode||'—' },
    { key:'city',                 label:'City',          vis:'field:net-city',     get:d=>d.geo?.city||'—' },
    { key:'timezone',             label:'Timezone',      vis:'field:net-tz',       get:d=>d.geo?.timezone||'—' },
    { key:'isPublic',             label:'Public',        vis:'field:net-public',   get:d=>d.geo?.isPublic },
    { key:'isWhitelisted',        label:'Whitelisted',   vis:'field:net-wl',       get:d=>d.geo?.isWhitelisted },
    { key:'hostnames',            label:'Hostnames',     vis:'field:net-hostnames',get:d=>d.geo?.hostnames||[] },
    { key:'abuseConfidenceScore', label:'Abuse %',       vis:'field:ab-score',     get:d=>d.abuseipdb?.confidenceScore??'—' },
    { key:'totalReports',         label:'Reports',       vis:'field:ab-reports',   get:d=>d.abuseipdb?.totalReports??'—' },
    { key:'lastReportedAt',       label:'Last Reported', vis:'field:ab-lastreport',get:d=>d.abuseipdb?.lastReportedAt?d.abuseipdb.lastReportedAt.replace('T',' ').replace('+00:00',''):'—' },
    { key:'vtStats_S_U_H',        label:'VT S/U/H',      vis:'field:vt-summary',   get:d=>d.virustotal?`${d.virustotal.suspicious}/${d.virustotal.undetected}/${d.virustotal.harmless}`:'—' },
    { key:'vtMalicious',          label:'VT Malicious',  vis:'field:vt-malicious', get:d=>d.virustotal?.malicious??'—' },
    { key:'vtSuspicious',         label:'VT Suspicious', vis:'field:vt-suspicious',get:d=>d.virustotal?.suspicious??'—' },
    { key:'vtReputation',         label:'VT Reputation', vis:'vt',                 get:d=>d.virustotal?.reputation??'—' },
    { key:'link_virustotal',      label:'VT Link',       vis:'field:link-vt',      get:d=>d.links?.virustotal||'' },
    { key:'link_abuseipdb',       label:'AbuseIPDB Link',vis:'field:link-abuse',   get:d=>d.links?.abuseipdb||'' },
    { key:'link_ipapi',           label:'IPAPI Link',    vis:'field:link-ipapi',   get:d=>d.links?.ipapi||'' },
];

export function isColVisible(col) {
    if (!col.vis) return true;
    if (col.vis.startsWith('field:')) return fieldVisible[col.vis.slice(6)] !== false;
    return colVisible[col.vis] !== false;
}

export const visibleTableCols = computed(() => TABLE_COLS.filter(c => isColVisible(c)));

export const sortedTableRows = computed(() => {
    const rows = allResults.value.filter(e=>e.result).map((e,i)=>({...e.result,_ip:e.ip,_idx:i}));
    const col = TABLE_COLS.find(c=>c.key===tableSortCol.value);
    if (col) rows.sort((a,b) => {
        let va = col.get(a,a._idx), vb = col.get(b,b._idx);
        if (typeof va==='boolean') va=va?1:0;
        if (typeof vb==='boolean') vb=vb?1:0;
        if (Array.isArray(va)) va=va.length;
        if (Array.isArray(vb)) vb=vb.length;
        return (va<vb?-1:va>vb?1:0) * (tableSortAsc.value?1:-1);
    });
    return rows;
});

export function sortTable(key) {
    if (tableSortCol.value===key) { tableSortAsc.value=!tableSortAsc.value; }
    else { tableSortCol.value=key; tableSortAsc.value=true; }
}

export function renderTableCell(col, row, i) {
    const val = col.get(row, i);
    if (col.key==='riskLevel') {
        const risk=val||'CLEAN';
        return `<span class="t-risk risk-${risk}">${risk}</span>`;
    }
    if (col.key==='isPublic'||col.key==='isWhitelisted') {
        if (val==null) return `<span class="t-na">—</span>`;
        return val ? `<span class="t-bool-yes">✓ Yes</span>` : `<span class="t-bool-no">✗ No</span>`;
    }
    if (col.key==='hostnames') {
        if (!val||!val.length) return `<span class="t-na">—</span>`;
        return val.map(h=>`<span class="t-hostname">${h}</span>`).join('');
    }
    if (col.key==='abuseConfidenceScore'&&typeof val==='number') {
        return `<span style="color:${abuseColor(val)};font-weight:600">${val}%</span>`;
    }
    if (col.key==='vtMalicious'&&typeof val==='number') {
        const c=val>=5?'#f87171':val>=1?'#fb923c':'#34d399';
        return `<span style="color:${c};font-weight:600">${val}</span>`;
    }
    if (col.key==='vtReputation'&&typeof val==='number') {
        const c=val>0?'#34d399':val<0?'#f87171':'#4d6480';
        return `<span style="color:${c}">${val}</span>`;
    }
    if (col.key==='link_virustotal') {
        if (!val) return `<span class="t-na">—</span>`;
        return `<a href="${val}" target="_blank" rel="noopener" class="tbl-link-chip">↗ VT</a>`;
    }
    if (col.key==='link_abuseipdb') {
        if (!val) return `<span class="t-na">—</span>`;
        return `<a href="${val}" target="_blank" rel="noopener" class="tbl-link-chip ab">↗ AbuseIPDB</a>`;
    }
    if (col.key==='link_ipapi') {
        if (!val) return `<span class="t-na">—</span>`;
        return `<a href="${val}" target="_blank" rel="noopener" class="tbl-link-chip ip">↗ IPAPI</a>`;
    }
    if (val==='—'||val==null) return `<span class="t-na">—</span>`;
    return String(val);
}

// ─── Table: Hash mode ─────────────────────────────────────────────────────────

export const visibleHashTableCols = computed(() => {
    const base = [{ key:'#', label:'#' }, { key:'hash', label:'Hash' }];
    const dyn  = hashDynCols.filter(c=>c.visible).map(c=>({ key:c.key, label:c.label }));
    return [...base, ...dyn];
});

export const sortedHashRows = computed(() => {
    const rows = allHashResults.value.map((e,i)=>({ ...(e.result||e), _idx:i, _hash:e.hash }));
    rows.sort((a,b) => {
        const va=getHashCellVal(a,hashSortCol.value), vb=getHashCellVal(b,hashSortCol.value);
        return (va<vb?-1:va>vb?1:0) * (hashSortAsc.value?1:-1);
    });
    return rows;
});

export function sortHashTable(key) {
    if (hashSortCol.value===key) hashSortAsc.value=!hashSortAsc.value;
    else { hashSortCol.value=key; hashSortAsc.value=true; }
}

export function getHashCellVal(d, key) {
    if (key==='#') return d._idx;
    if (key==='hash') return d._hash||d.virustotal?.sha256||d.virustotal?.sha1||d.virustotal?.md5||'';
    if (key==='riskLevel')         return d.riskLevel||'—';
    if (key==='hashType')          return d.hashType||'—';
    if (key==='link_virustotal')   return d.links?.virustotal||'—';
    if (key==='link_malwarebazaar')return d.links?.malwarebazaar||'—';

    const vtMap = {
        vtMalicious:'malicious', vtSuspicious:'suspicious', vtHarmless:'harmless',
        vtUndetected:'undetected', vtReputation:'reputation',
        meaningfulName:'meaningfulName', magic:'magic', magika:'magika',
        md5:'md5', sha1:'sha1', sha256:'sha256',
        suggestedThreatLabel:'suggestedThreatLabel',
        popularThreatCategories:'popularThreatCategories',
        popularThreatNames:'popularThreatNames',
        sandboxMalwareClassifications:'sandboxMalwareClassifications',
        sigmaAnalysisSummary:'sigmaAnalysisSummary',
        signatureSigners:'signatureSigners',
        signerDetail:'signerDetail',
    };
    if (key in vtMap) {
        const v = d.virustotal?.[vtMap[key]];
        if (v==null) return '—';
        if (Array.isArray(v)) return v.join(', ')||'—';
        if (typeof v==='object') return JSON.stringify(v);
        return String(v);
    }

    const mbMap = {
        mbQueryStatus:'queryStatus', mbFileName:'fileName', mbFileType:'fileType',
        mbSignature:'signature', mbTags:'tags', mbComment:'comment',
    };
    if (key in mbMap) {
        const v = d.malwarebazaar?.[mbMap[key]];
        if (v==null) return '—';
        if (Array.isArray(v)) return v.join(', ')||'—';
        return String(v);
    }

    const v = d[key];
    if (v==null) return '—';
    if (Array.isArray(v)) return v.join(', ')||'—';
    if (typeof v==='object') return JSON.stringify(v);
    return String(v);
}

export function renderHashTableCell(col, row) {
    if (col.key==='#') return String(row._idx+1);
    if (col.key==='hash') {
        const h=row._hash||row.virustotal?.sha256||row.virustotal?.sha1||row.virustotal?.md5||'?';
        return `<span style="font-size:0.65rem">${h.slice(0,16)}…</span>`;
    }
    if (col.key==='riskLevel') {
        const r=row.riskLevel||'CLEAN';
        return `<span class="t-risk risk-${r}">${r}</span>`;
    }
    if (col.key==='mbQueryStatus') {
        const raw=row.malwarebazaar?.queryStatus;
        const color=raw==='ok'?'#34d399':raw==='hash_not_found'?'#4d6480':'#94a3b8';
        const label=raw==='ok'?'Found':raw==='hash_not_found'?'Not found':raw||'—';
        return `<span style="color:${color};font-weight:${raw==='ok'?700:400}">${label}</span>`;
    }
    if (col.key==='link_virustotal') {
        const url=row.links?.virustotal;
        if (!url) return `<span class="t-na">—</span>`;
        const vt=row.virustotal||{};
        const notFound=vt.malicious===0&&vt.suspicious===0&&vt.harmless===0&&vt.undetected===0&&!vt.meaningfulName;
        return notFound
            ? `<span class="tbl-link-na" title="Not found in VirusTotal">✗ VT</span>`
            : `<a href="${url}" target="_blank" rel="noopener" class="tbl-link-chip">↗ VT</a>`;
    }
    if (col.key==='link_malwarebazaar') {
        const url=row.links?.malwarebazaar;
        if (!url) return `<span class="t-na">—</span>`;
        const notFound=row.malwarebazaar?.queryStatus&&row.malwarebazaar.queryStatus!=='ok';
        return notFound
            ? `<span class="tbl-link-na" title="Not found in MalwareBazaar">✗ MB</span>`
            : `<a href="${url}" target="_blank" rel="noopener" class="tbl-link-chip ab">↗ MB</a>`;
    }
    const val=getHashCellVal(row,col.key);
    if (val==='—') return `<span class="t-na">—</span>`;
    if (col.key==='vtMalicious'&&typeof val==='string'&&val!=='—') {
        const n=parseInt(val); const c=n>=5?'#f87171':n>=1?'#fb923c':'#34d399';
        return `<span style="color:${c};font-weight:600">${val}</span>`;
    }
    if (col.key==='vtReputation'&&typeof val==='string'&&val!=='—') {
        const n=parseInt(val); const c=n>0?'#34d399':n<0?'#f87171':'#4d6480';
        return `<span style="color:${c}">${val}</span>`;
    }
    const display=val.length>60?val.slice(0,58)+'…':val;
    return `<span title="${val.replace(/"/g,'&quot;')}">${display}</span>`;
}

// ─── API calls ────────────────────────────────────────────────────────────────

export async function doIPScan() {
    const ip = ipInputText.value.trim();
    if (!ip) { ipError.value = 'Enter at least one IP address.'; return; }
    ipError.value = '';
    isIPLoading.value = true;
    try {
        const res = await fetch('/api/scan', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({
                ip, mode:scanMode.value,
                vt_key:keys.vt, abuse_key:keys.abuse,
                ipapi_key:keys.ipapi, abusech_key:keys.abusech,
                use_cache:ipUseCache.value,
            }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
        allResults.value = data;
        activeIdx.value  = 0;
        data.forEach(e => { if (e.result) addHist(e.ip, e.result.riskLevel||'CLEAN'); });
        if (currentView.value === 'table') tableSortCol.value = '#';
        nextTick(() => { document.getElementById('cardsView')?.scrollIntoView({ behavior:'smooth', block:'start' }); });
    } catch(e) {
        ipError.value = `Scan failed: ${e.message}`;
    } finally {
        isIPLoading.value = false;
    }
}

export async function doHashScanAction() {
    const raw = hashInputText.value.trim();
    if (!raw) { hashError.value = 'Please enter at least one hash.'; return; }
    const hashes = extractHashes(raw);
    if (!hashes.length) { hashError.value = 'No valid MD5/SHA1/SHA256 hashes found.'; return; }
    hashError.value  = '';
    isHashLoading.value = true;
    try {
        const resp = await fetch('/api/scan/hash', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({ hashes, vt_key:keys.vt, abusech_key:keys.abusech, use_cache:hashUseCache.value }),
        });
        if (!resp.ok) { const t = await resp.text(); throw new Error(t || resp.statusText); }
        const data = await resp.json();
        allHashResults.value = data;
        activeHashIdx.value  = 0;
        buildHashDynCols(data);
        data.forEach(e => {
            const r = e.result||e;
            addHist(e.hash||r.virustotal?.sha256||r.virustotal?.md5||'?', r.riskLevel||(e.error?'ERROR':'UNKNOWN'));
        });
    } catch(err) {
        hashError.value = 'Hash scan error: ' + err.message;
    } finally {
        isHashLoading.value = false;
    }
}

// ─── History ──────────────────────────────────────────────────────────────────

export function addHist(ip, risk) {
    const time = new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
    const existing = scanHist.findIndex(h => h.ip === ip);
    if (existing !== -1) {
        scanHist[existing].risk = risk;
        scanHist[existing].lastSeen = time;
        scanHist[existing].scanCount = (scanHist[existing].scanCount||1) + 1;
    } else {
        scanHist.unshift({ ip, risk, time, lastSeen:time, scanCount:1 });
        if (scanHist.length > 20) scanHist.pop();
    }
}

export function clearHistory() { scanHist.splice(0, scanHist.length); }

export function reScan(ip) { ipInputText.value = ip; doIPScan(); }

// ─── Drawer controls ──────────────────────────────────────────────────────────

export function openColDrawer()  { colDrawerOpen.value = true;  histDrawerOpen.value = false; }
export function closeColDrawer() { colDrawerOpen.value = false; }
export function toggleHistDrawer() {
    histDrawerOpen.value = !histDrawerOpen.value;
    colDrawerOpen.value  = false;
}

// ─── Mode / view ──────────────────────────────────────────────────────────────

export function switchIOCMode(mode) {
    currentIOCMode.value = mode;
    colDrawerOpen.value  = false;
    histDrawerOpen.value = false;
}

export function setView(mode)     { currentView.value = mode; }
export function setHashView(mode) { hashView.value    = mode; }

// ─── Tab switching ────────────────────────────────────────────────────────────

export function switchTab(i)          { activeIdx.value = i; }
export function switchToCard(idx)     { activeIdx.value = idx; setView('cards'); }

const RISK_DOT_COLOR = { CRITICAL:'#f87171', HIGH:'#fb923c', MEDIUM:'#fbbf24', LOW:'#94a3b8', CLEAN:'#34d399' };
export function riskDotColor(risk)    { return RISK_DOT_COLOR[risk] || '#2e4060'; }

// ─── IOC extraction ───────────────────────────────────────────────────────────

export function extractIPs(text) {
    const ipv4=/\b(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\b/g;
    const ipv6=/\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g;
    const found=[...(text.match(ipv4)||[]),...(text.match(ipv6)||[])];
    return [...new Map(found.map(ip=>[ip,ip])).values()];
}

export function extractHashes(text) {
    const sha256=/\b[a-fA-F0-9]{64}\b/g, sha1=/\b[a-fA-F0-9]{40}\b/g, md5=/\b[a-fA-F0-9]{32}\b/g;
    const found=[...(text.match(sha256)||[]),...(text.match(sha1)||[]),...(text.match(md5)||[])];
    return [...new Map(found.map(h=>[h.toLowerCase(),h.toLowerCase()])).values()];
}

// ─── File upload / drag-drop ──────────────────────────────────────────────────

export function handleIPFileUpload(event) {
    const file=event.target.files[0]; if (!file) return;
    const reader=new FileReader();
    reader.onload=e=>{
        const ips=extractIPs(e.target.result);
        if (!ips.length) { ipError.value='No valid IP addresses found in file.'; return; }
        ipInputText.value=ips.join('\n'); ipBulkCount.value=ips.length;
    };
    reader.readAsText(file); event.target.value='';
}

export function handleIPDrop(e) {
    isDragging.value=false;
    const file=e.dataTransfer.files[0]; if (!file) return;
    const reader=new FileReader();
    reader.onload=ev=>{
        const ips=extractIPs(ev.target.result);
        if (!ips.length) { ipError.value='No valid IPs found.'; return; }
        ipInputText.value=ips.join('\n'); ipBulkCount.value=ips.length;
    };
    reader.readAsText(file);
}

export function clearIPBulk() { ipInputText.value=''; ipBulkCount.value=0; }

export function handleHashFileUpload(event) {
    const file=event.target.files[0]; if (!file) return;
    const reader=new FileReader();
    reader.onload=e=>{
        const hashes=extractHashes(e.target.result);
        if (!hashes.length) { hashError.value='No valid hashes found in file.'; return; }
        hashInputText.value=hashes.join('\n'); hashBulkCount.value=hashes.length;
    };
    reader.readAsText(file); event.target.value='';
}

export function clearHashBulk() { hashInputText.value=''; hashBulkCount.value=0; }

// Watch bulk counts
watch(ipInputText,   v => { ipBulkCount.value   = v.trim() ? extractIPs(v).length     : 0; });
watch(hashInputText, v => { hashBulkCount.value  = v.trim() ? extractHashes(v).length  : 0; });

// ─── Export / copy ────────────────────────────────────────────────────────────

export function toggleCopyMenu()     { copyMenuOpen.value     = !copyMenuOpen.value; }
export function toggleHashCopyMenu() { hashCopyMenuOpen.value = !hashCopyMenuOpen.value; }

export function copyJSON() {
    const d = activeResult.value;
    if (!d) return;
    navigator.clipboard.writeText(JSON.stringify(d, null, 2));
}

export function copyHashJSON() {
    const d = activeHashResult.value;
    if (!d) return;
    navigator.clipboard.writeText(JSON.stringify(d, null, 2));
}

export async function copyClipboard(format) {
    copyMenuOpen.value = false;
    const rows = allResults.value.filter(e=>e.result).map(e=>e.result);
    if (!rows.length) return;
    let text = '';
    if (format==='json') {
        text = JSON.stringify(buildFilteredRows(), null, 2);
    } else if (format==='csv') {
        const cols = TABLE_COLS.filter(c => c.key !== '#' && isColVisible(c));
        const header = cols.map(c => c.label).join(',');
        const lines  = rows.map(row => cols.map(c => {
            let v = c.get(row);
            if (Array.isArray(v)) v = v.join('; ');
            if (typeof v==='boolean') v = v ? 'true' : 'false';
            if (v==null||v==='—') v='';
            return '"' + String(v).replace(/"/g,'""') + '"';
        }).join(','));
        text = [header, ...lines].join('\n');
    } else if (format==='ips') {
        text = rows.map(r=>r.ipAddress||r.ip).filter(Boolean).join('\n');
    }
    try {
        await navigator.clipboard.writeText(text);
    } catch(e) {
        const ta=document.createElement('textarea'); ta.value=text;
        ta.style.cssText='position:fixed;opacity:0'; document.body.appendChild(ta);
        ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
    }
}

export async function copyHashClipboard(format) {
    hashCopyMenuOpen.value = false;
    const rows = allHashResults.value.filter(e=>e.result).map(e=>e.result||e);
    if (!rows.length) return;
    let text = '';
    if (format==='json') {
        text = JSON.stringify(rows.map(buildHashExportRow), null, 2);
    } else if (format==='csv') {
        const { header, lines } = buildHashCSV(rows);
        text = [header, ...lines].join('\n');
    } else if (format==='hashes') {
        text = rows.map(r=>r.virustotal?.sha256||r.virustotal?.sha1||r.virustotal?.md5||r._hash||r.hash).filter(Boolean).join('\n');
    }
    try {
        await navigator.clipboard.writeText(text);
        const btn = document.getElementById('hashClipboardBtn');
        if (btn) { const orig=btn.textContent; btn.textContent='✓ Copied!'; setTimeout(()=>btn.textContent=orig,2000); }
    } catch(e) {
        const ta=document.createElement('textarea'); ta.value=text;
        ta.style.cssText='position:fixed;opacity:0'; document.body.appendChild(ta);
        ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
    }
}

export function exportCSV() {
    const rows = allResults.value.filter(e=>e.result).map(e=>e.result);
    if (!rows.length) return;
    const cols   = TABLE_COLS.filter(c => c.key !== '#' && isColVisible(c));
    const header = cols.map(c => c.label).join(',');
    const lines  = rows.map(row => cols.map(c => {
        let v = c.get(row);
        if (Array.isArray(v)) v = v.join('; ');
        if (typeof v==='boolean') v = v ? 'true' : 'false';
        if (v==null||v==='—') v='';
        return '"' + String(v).replace(/"/g,'""') + '"';
    }).join(','));
    download([header, ...lines].join('\n'), 'iocscan_results.csv', 'text/csv');
}

export function exportJSON() {
    const data=buildFilteredRows();
    if (!data.length) return;
    download(JSON.stringify(data,null,2),'iocscan_results.json','application/json');
}

export function exportHashCSV() {
    const rows = allHashResults.value.filter(e=>e.result).map(e=>e.result||e);
    if (!rows.length) return;
    const { header, lines } = buildHashCSV(rows);
    download([header,...lines].join('\n'), 'iocscan_hash_results.csv', 'text/csv');
}

export function exportHashJSON() {
    const rows = allHashResults.value.filter(e=>e.result).map(e=>e.result||e);
    if (!rows.length) return;
    download(JSON.stringify(rows.map(buildHashExportRow),null,2), 'iocscan_hash_results.json','application/json');
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

export function yn(b)          { return b ? '✓ Yes' : '✗ No'; }
export function abuseColor(s)  { return s>=75?'#f87171':s>=40?'#fb923c':s>0?'#fbbf24':'#34d399'; }
export function formatBytes(b) {
    if (!b) return '—';
    if (b<1024)    return b+' B';
    if (b<1048576) return (b/1024).toFixed(1)+' KB';
    return (b/1048576).toFixed(2)+' MB';
}

export function toArr(v) {
    if (!v) return [];
    if (Array.isArray(v)) return v;
    if (typeof v==='string' && v.trim()) return [v];
    return [];
}

export function vtStatPart(idx) {
    const d = activeResult.value;
    if (!d || !d.virustotal) return '—';
    const vt = d.virustotal;
    return [vt.suspicious ?? 0, vt.undetected ?? 0, vt.harmless ?? 0][idx] ?? '—';
}

function highlight(json) {
    return json.replace(
        /("(?:\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*"(\s*:)?|true|false|null|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
        m => {
            if (/^"/.test(m)) return /:$/.test(m)?`<span class="j-k">${m}</span>`:`<span class="j-s">${m}</span>`;
            if (/true|false/.test(m)) return `<span class="j-b">${m}</span>`;
            if (/null/.test(m))       return `<span class="j-0">${m}</span>`;
            return `<span class="j-n">${m}</span>`;
        }
    );
}

function download(content, filename, type) {
    const blob=new Blob([content],{type});
    const a=document.createElement('a'); a.href=URL.createObjectURL(blob);
    a.download=filename; a.click();
}

function buildFilteredRows() {
    const cols = TABLE_COLS.filter(c => c.key !== '#' && isColVisible(c));
    return allResults.value.filter(e=>e.result).map((e,i) => {
        const obj = {};
        cols.forEach(c => {
            let v = c.get(e.result, i);
            if (v==='—') v=null;
            if (typeof v==='boolean') v=v?true:false;
            if (Array.isArray(v)) v=v.join('; ');
            const exportKey = c.key==='link_virustotal'?'virustotal_link'
                : c.key==='link_abuseipdb' ?'abuseipdb_link'
                    : c.key==='link_ipapi'      ?'ipapi_link'
                        : c.key;
            obj[exportKey] = v||null;
        });
        return obj;
    });
}

function buildHashExportRow(row) {
    const cols = hashDynCols.filter(c=>c.visible);
    const obj  = {};
    cols.forEach(c => {
        let v = getHashCellVal(row, c.key);
        if (v==='—') v=null;
        const exportKey = c.key==='link_virustotal'   ?'virustotal_link'
            : c.key==='link_malwarebazaar' ?'malwarebazaar_link'
                : c.key;
        obj[exportKey] = v;
    });
    return obj;
}

function buildHashCSV(rows) {
    const cols   = hashDynCols.filter(c=>c.visible);
    const header = cols.map(c=>c.label).join(',');
    const lines  = rows.map(row => cols.map(c => {
        let v = getHashCellVal(row, c.key);
        if (v==null||v==='—') v='';
        return '"' + String(v).replace(/"/g,'""') + '"';
    }).join(','));
    return { header, lines };
}