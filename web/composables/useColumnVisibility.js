// composables/useColumnVisibility.js
// ─────────────────────────────────────────────────────────────────────────────
// All column & field visibility state, toggle functions, badge helper,
// and drawer section builders for both IP mode and Hash mode.
//
// Uses the Vue 3 GLOBAL build (window.Vue) — no bundler required.
// ─────────────────────────────────────────────────────────────────────────────

const { reactive } = Vue;

// ─── IP mode ──────────────────────────────────────────────────────────────────

export const colVisible = reactive({
    risk: true, network: true, abuse: true, vt: true, links: true, json: true,
});

export const fieldVisible = reactive({
    'net-ip':true,'net-isp':true,'net-country':true,'net-city':true,
    'net-tz':true,'net-localtime':true,'net-company':true,'net-companytype':true,
    'net-companydomain':true,'net-abuserscore':true,'net-vpnservice':true,'net-vpntype':true,
    'net-vpn':true,'net-proxy':true,'net-tor':true,'net-datacenter':true,'net-crawler':true,
    'net-abuser':true,'net-bogon':true,'net-mobile':true,'net-satellite':true,
    'net-public':true,'net-wl':true,'net-hostnames':true,
    'ab-score':true,'ab-meter':true,'ab-reports':true,'ab-lastreport':true,
    'vt-malicious':true,'vt-suspicious':true,'vt-harmless':true,
    'vt-undetected':true,'vt-summary':true,
    'link-vt':true,'link-abuse':true,'link-ipapi':true,
});

const SECTION_FIELDS = {
    network: ['net-ip','net-isp','net-country','net-city','net-tz','net-localtime','net-company','net-companytype','net-companydomain','net-abuserscore','net-vpnservice','net-vpntype','net-vpn','net-proxy','net-tor','net-datacenter','net-crawler','net-abuser','net-bogon','net-mobile','net-satellite','net-public','net-wl','net-hostnames'],
    abuse:   ['ab-score','ab-meter','ab-reports','ab-lastreport'],
    vt:      ['vt-malicious','vt-suspicious','vt-harmless','vt-undetected','vt-summary'],
    links:   ['link-vt','link-abuse','link-ipapi'],
};

// ─── Hash mode ────────────────────────────────────────────────────────────────

export const hashDynCols    = reactive([]);
export const hashColVisible = reactive({});

export const HASH_COL_LABELS = {
    riskLevel:'Risk', hashType:'Type', meaningfulName:'Name', magic:'Magic', magika:'Magika',
    vtMalicious:'VT Malicious', vtSuspicious:'VT Suspicious', vtHarmless:'VT Harmless',
    vtUndetected:'VT Undetected', vtReputation:'VT Reputation',
    suggestedThreatLabel:'Threat', popularThreatCategories:'VT Categories',
    popularThreatNames:'VT Names', mbQueryStatus:'MB Status', mbSignature:'MB Signature',
    mbFileName:'MB File Name', mbFileType:'MB Type', mbTags:'MB Tags', mbComment:'MB Comment',
    signatureSigners:'Code Signer', sigmaAnalysisSummary:'Sigma',
    sandboxMalwareClassifications:'Sandbox', signerDetail:'Signer Detail',
    md5:'Md5', sha1:'Sha1', sha256:'Sha256',
    link_virustotal:'VT Link', link_malwarebazaar:'MB Link',
};

export const HASH_COL_ORDER = [
    'riskLevel','hashType','meaningfulName','magic','magika',
    'vtMalicious','vtSuspicious','vtHarmless','vtUndetected','vtReputation',
    'suggestedThreatLabel','popularThreatCategories','popularThreatNames',
    'mbQueryStatus','mbSignature','mbFileName','mbFileType','mbTags','mbComment',
    'signatureSigners','sigmaAnalysisSummary','sandboxMalwareClassifications',
    'signerDetail','md5','sha1','sha256',
    'link_virustotal','link_malwarebazaar',
];

export const HASH_COL_HIDDEN_DEFAULT = new Set([
    'popularThreatCategories','popularThreatNames','sigmaAnalysisSummary',
    'sandboxMalwareClassifications','signerDetail','md5','sha1','sha256',
]);

export const HASH_SECTION_DEFS = [
    { key:'hfile',  icon:'📄', label:'File Info',     keys:['riskLevel','hashType','meaningfulName','magic','magika','signatureSigners','signerDetail'] },
    { key:'hvt',    icon:'🧪', label:'VirusTotal',    keys:['vtMalicious','vtSuspicious','vtHarmless','vtUndetected','vtReputation','suggestedThreatLabel','popularThreatCategories','popularThreatNames','sigmaAnalysisSummary','sandboxMalwareClassifications'] },
    { key:'hmb',    icon:'🦠', label:'MalwareBazaar', keys:['mbQueryStatus','mbSignature','mbFileName','mbFileType','mbTags','mbComment'] },
    { key:'hhash',  icon:'⬡',  label:'Hash Values',   keys:['md5','sha1','sha256'] },
    { key:'hlinks', icon:'🔗', label:'Links',         keys:['link_virustotal','link_malwarebazaar'] },
];

// ─── Toggle functions ─────────────────────────────────────────────────────────

export function toggleCol(key) {
    colVisible[key] = !colVisible[key];
}

export function toggleSection(key) {
    colVisible[key] = !colVisible[key];
    if (SECTION_FIELDS[key]) {
        SECTION_FIELDS[key].forEach(f => { fieldVisible[f] = colVisible[key]; });
    }
}

export function toggleField(key) {
    fieldVisible[key] = !fieldVisible[key];
}

export function toggleHashCol(key) {
    const c = hashDynCols.find(c => c.key === key);
    if (c) { c.visible = !c.visible; hashColVisible[key] = c.visible; }
}

export function toggleHashSection(secKey) {
    const KEYS = Object.fromEntries(HASH_SECTION_DEFS.map(d => [d.key, d.keys]));
    let cols;
    if (secKey === 'hother') {
        const allKeyed = new Set(Object.values(KEYS).flat());
        cols = hashDynCols.filter(c => !allKeyed.has(c.key));
    } else {
        cols = hashDynCols.filter(c => (KEYS[secKey] || []).includes(c.key));
    }
    if (!cols.length) return;
    const newVal = !cols.every(c => c.visible);
    cols.forEach(c => { c.visible = newVal; hashColVisible[c.key] = newVal; });
}

export function setAllCols(visible, currentIOCMode) {
    if (currentIOCMode === 'hash') {
        hashDynCols.forEach(c => { c.visible = visible; hashColVisible[c.key] = visible; });
    } else {
        Object.keys(colVisible).forEach(k => { colVisible[k] = visible; });
        Object.keys(fieldVisible).forEach(f => { fieldVisible[f] = visible; });
    }
}

// ─── Build hash dynamic columns from scan results ─────────────────────────────

export function buildHashDynCols(results) {
    const hasData = new Set();
    results.forEach(e => {
        const r = e.result || e;
        if (!r) return;
        const vt = r.virustotal || {};
        const mb = r.malwarebazaar || {};
        if (vt.md5)                               hasData.add('md5');
        if (vt.sha1)                              hasData.add('sha1');
        if (vt.sha256)                            hasData.add('sha256');
        if (vt.meaningfulName)                    hasData.add('meaningfulName');
        if (vt.magic)                             hasData.add('magic');
        if (vt.magika)                            hasData.add('magika');
        if (vt.malicious != null)                 hasData.add('vtMalicious');
        if (vt.suspicious != null)                hasData.add('vtSuspicious');
        if (vt.harmless != null)                  hasData.add('vtHarmless');
        if (vt.undetected != null)                hasData.add('vtUndetected');
        if (vt.reputation != null)                hasData.add('vtReputation');
        if (vt.suggestedThreatLabel)              hasData.add('suggestedThreatLabel');
        if (vt.popularThreatCategories?.length)   hasData.add('popularThreatCategories');
        if (vt.popularThreatNames?.length)        hasData.add('popularThreatNames');
        if (vt.sandboxMalwareClassifications?.length) hasData.add('sandboxMalwareClassifications');
        if (vt.sigmaAnalysisSummary)              hasData.add('sigmaAnalysisSummary');
        if (vt.signatureSigners)                  hasData.add('signatureSigners');
        if (vt.signerDetail)                      hasData.add('signerDetail');
        if (mb.queryStatus)                       hasData.add('mbQueryStatus');
        if (mb.signature)                         hasData.add('mbSignature');
        if (mb.fileName)                          hasData.add('mbFileName');
        if (mb.fileType)                          hasData.add('mbFileType');
        if (mb.tags?.length)                      hasData.add('mbTags');
        if (mb.comment)                           hasData.add('mbComment');
        if (r.riskLevel)                          hasData.add('riskLevel');
        if (r.hashType)                           hasData.add('hashType');
        if (r.links?.virustotal)                  hasData.add('link_virustotal');
        if (r.links?.malwarebazaar)               hasData.add('link_malwarebazaar');
    });

    const skip = new Set(['hash','_hash','threatfox','links']);
    const ordered = HASH_COL_ORDER.filter(k => !skip.has(k));

    hashDynCols.splice(0, hashDynCols.length, ...ordered.map(key => {
        const prev = hashDynCols.find(c => c.key === key);
        const defaultVisible = hasData.has(key) && !HASH_COL_HIDDEN_DEFAULT.has(key);
        const visible = prev
            ? prev.visible
            : (hashColVisible[key] !== undefined ? hashColVisible[key] : defaultVisible);
        return { key, label: HASH_COL_LABELS[key] || key, visible };
    }));
}

// ─── Column badge text ────────────────────────────────────────────────────────
// Called as a regular function (not computed) — caller wraps in computed if needed.

export function makeColBadge(currentIOCMode) {
    if (currentIOCMode === 'hash' && hashDynCols.length) {
        const on = hashDynCols.filter(c => c.visible).length;
        return on + '/' + hashDynCols.length;
    }
    const allToggs = [...Object.values(colVisible), ...Object.values(fieldVisible)];
    const on = allToggs.filter(Boolean).length;
    return on + '/' + allToggs.length;
}

// ─── Drawer section builders ──────────────────────────────────────────────────

export function makeIpDrawerSections(allResults, activeIdx) {
    if (!allResults.length) return [];
    const d = allResults[activeIdx]?.result;
    if (!d) return [];
    const sections = [];
    if (d.riskLevel != null) sections.push({ key:'risk', icon:'🏷', label:'Risk Pill', fields:[] });
    const netFields = [
        { key:'net-ip',        label:'IP Address',  present:!!(d.ipAddress||d.ip) },
        { key:'net-isp',       label:'ISP',         present:!!(d.geo?.isp||d.geo?.asn_org) },
        { key:'net-country',   label:'Country',     present:!!(d.geo?.country||d.geo?.countryCode) },
        { key:'net-city',      label:'City',        present:!!d.geo?.city },
        { key:'net-tz',        label:'Timezone',    present:!!d.geo?.timezone },
        { key:'net-localtime', label:'Local Time',  present:!!d.geo?.localTime },
        { key:'net-company',   label:'Company',     present:!!d.geo?.companyName },
        { key:'net-companytype', label:'Company Type', present:!!d.geo?.companyType },
        { key:'net-companydomain', label:'Company Domain', present:!!d.geo?.companyDomain },
        { key:'net-abuserscore', label:'Abuser Score', present:!!d.geo?.abuserScore },
        { key:'net-vpnservice', label:'VPN Service', present:!!d.geo?.vpnService },
        { key:'net-vpntype',   label:'VPN Type',    present:!!d.geo?.vpnType },
        { key:'net-vpn',       label:'VPN',         present:!!d.geo?.isVPN },
        { key:'net-proxy',     label:'Proxy',       present:!!d.geo?.isProxy },
        { key:'net-tor',       label:'Tor',         present:!!d.geo?.isTor },
        { key:'net-datacenter', label:'Datacenter', present:!!d.geo?.isDatacenter },
        { key:'net-crawler',   label:'Crawler',     present:!!d.geo?.isCrawler },
        { key:'net-abuser',    label:'Abuser',      present:!!d.geo?.isAbuser },
        { key:'net-bogon',     label:'Bogon',       present:!!d.geo?.isBogon },
        { key:'net-mobile',    label:'Mobile',      present:!!d.geo?.isMobile },
        { key:'net-satellite', label:'Satellite',   present:!!d.geo?.isSatellite },
        { key:'net-public',    label:'Public',      present:d.geo?.isPublic!=null },
        { key:'net-wl',        label:'Whitelisted', present:d.geo?.isWhitelisted!=null },
        { key:'net-hostnames', label:'Hostnames',   present:true },
    ].filter(f => f.present);
    if (netFields.length) sections.push({ key:'network', icon:'🌍', label:'Network Info', fields:netFields });
    const abuseFields = [
        { key:'ab-score',     label:'Confidence Score', present:d.abuseipdb?.confidenceScore!=null },
        { key:'ab-meter',     label:'Score Meter',      present:d.abuseipdb?.confidenceScore!=null },
        { key:'ab-reports',   label:'Total Reports',    present:d.abuseipdb?.totalReports!=null },
        { key:'ab-lastreport',label:'Last Reported',    present:!!d.abuseipdb?.lastReportedAt },
    ].filter(f => f.present);
    if (abuseFields.length) sections.push({ key:'abuse', icon:'🚨', label:'AbuseIPDB', fields:abuseFields });
    const vtFields = [
        { key:'vt-malicious',  label:'🔴 Malicious',  present:d.virustotal?.malicious!=null },
        { key:'vt-suspicious', label:'🟡 Suspicious', present:d.virustotal?.suspicious!=null },
        { key:'vt-harmless',   label:'🟢 Harmless',   present:d.virustotal!=null },
        { key:'vt-undetected', label:'⬜ Undetected', present:d.virustotal!=null },
        { key:'vt-summary',    label:'Summary S/U/H', present:d.virustotal!=null },
    ].filter(f => f.present);
    if (vtFields.length) sections.push({ key:'vt', icon:'🧪', label:'VirusTotal', fields:vtFields });
    const linkFields = [
        { key:'link-vt',    label:'VirusTotal Link', present:!!d.links?.virustotal },
        { key:'link-abuse', label:'AbuseIPDB Link',  present:!!d.links?.abuseipdb },
        { key:'link-ipapi', label:'IPAPI Link',      present:!!d.links?.ipapi },
    ].filter(f => f.present);
    if (linkFields.length) sections.push({ key:'links', icon:'🔗', label:'Links', fields:linkFields });
    sections.push({ key:'json', icon:'{ }', label:'Raw JSON', fields:[] });
    return sections;
}

export function makeHashDrawerSections() {
    const keyedSet = new Set(HASH_SECTION_DEFS.flatMap(s => s.keys));
    const otherCols = hashDynCols.filter(c => !keyedSet.has(c.key));
    const result = [];
    for (const def of HASH_SECTION_DEFS) {
        const cols = hashDynCols.filter(c => def.keys.includes(c.key));
        if (!cols.length) continue;
        result.push({ key:def.key, icon:def.icon, label:def.label, cols, allOn:cols.every(c=>c.visible) });
    }
    if (otherCols.length) {
        result.push({ key:'hother', icon:'⋯', label:'Other', cols:otherCols, allOn:otherCols.every(c=>c.visible) });
    }
    return result;
}
