// components/IOCScanner.js
// ─────────────────────────────────────────────────────────────────────────────
// Root application component. Imports all state from composables and
// child components. The template is the full application UI, faithfully
// preserving every element from the original index.html.
// ─────────────────────────────────────────────────────────────────────────────

import ColumnDrawer from './ColumnDrawer.js';
import ResultsTable from './ResultsTable.js';
import {
    currentUser,
    isAdmin,
    goToSettings,
    goToAdmin,
    logout,
} from '../composables/useAuth.js';

import {
    // State
    ipInputText, hashInputText,
    ipUseCache, hashUseCache, isDragging,
    ipBulkCount, hashBulkCount,
    currentIOCMode, currentView, hashView, wideShell,
    allResults, activeIdx, allHashResults, activeHashIdx,
    isIPLoading, isHashLoading, ipError, hashError,
    scanHist, histDrawerOpen, colDrawerOpen,
    copyMenuOpen, hashCopyMenuOpen,
    tableSortCol, tableSortAsc, hashSortCol, hashSortAsc,
    // Column visibility (for template v-show bindings)
    colVisible, fieldVisible,
    // Computed
    colBadge,
    activeResultEntry, activeResultIP, activeResult,
    activeHashEntry, activeHashResult,
    hashResultLinks, signerDetailObj, signerIsRevoked, signerIsInvalid, signerIsValid, vtNotFound,
    networkRows, highlightedJSON, highlightedHashJSON,
    visibleTableCols, sortedTableRows,
    visibleHashTableCols, sortedHashRows,
    // Methods
    switchIOCMode, setView, setHashView, switchTab, switchToCard,
    riskDotColor, vtStatPart, abuseColor, formatBytes, toArr, yn,
    openColDrawer, closeColDrawer, toggleHistDrawer,
    clearHistory, reScan, resetScanState,
    doIPScan, doHashScanAction,
    handleIPFileUpload, handleIPDrop, clearIPBulk,
    handleHashFileUpload, clearHashBulk,
    copyJSON, copyHashJSON,
    toggleCopyMenu, toggleHashCopyMenu,
    copyClipboard, copyHashClipboard,
    exportCSV, exportJSON, exportHashCSV, exportHashJSON,
    sortTable, renderTableCell, sortHashTable, renderHashTableCell,
    // Domain
    allDomainResults, activeDomainIdx, activeDomainResult, activeDomainEntry,
    domainError, isDomainLoading, domainBulkCount, domainInputText, domainUseCache,
    domainView, domainResultLinks, highlightedDomainJSON,
    visibleDomainTableCols, sortedDomainRows, domainSortCol, domainSortAsc,
    sortDomainTable, renderDomainTableCell,
    copyDomainJSON, exportDomainCSV, exportDomainJSON,
    doDomainScan, setDomainView, clearDomainBulk, handleDomainFileUpload,
} from '../composables/useIOCScan.js';

const { defineComponent } = Vue;
const CACHE_SOURCE_LABELS = {
    virustotal_ip: 'VirusTotal',
    abuseipdb: 'AbuseIPDB',
    ipapi: 'ipapi.is',
    threatfox_ip: 'ThreatFox',
    greynoise: 'GreyNoise',
    virustotal_hash: 'VirusTotal',
    malwarebazaar: 'MalwareBazaar',
    threatfox_hash: 'ThreatFox',
    virustotal_domain: 'VirusTotal',
    threatfox_domain: 'ThreatFox',
    malwarebazaar: 'MalwareBazaar',
};

export default defineComponent({
    name: 'IOCScanner',
    components: { ColumnDrawer, ResultsTable },

    setup() {
        async function logoutNow() {
            resetScanState();
            await logout();
        }

        function cacheHitLabels(result) {
            if (!result || !result.cacheHits) return [];
            return Object.keys(result.cacheHits)
                .filter(key => result.cacheHits[key])
                .map(key => CACHE_SOURCE_LABELS[key] || key);
        }

        function hasCacheHits(result) {
            return cacheHitLabels(result).length > 0;
        }

        function diagnosticEntries(result) {
            if (!result || !result.diagnostics) return [];
            return Object.keys(result.diagnostics)
                .sort()
                .map(key => ({
                    key,
                    label: CACHE_SOURCE_LABELS[key] || key,
                    cache: result.diagnostics[key].cache || 'live',
                    status: result.diagnostics[key].status || 'unknown',
                    error: result.diagnostics[key].error || '',
                }));
        }

        function diagnosticCacheLabel(cache) {
            return cache === 'hit' ? 'Cached' : 'Live';
        }

        function diagnosticCacheClass(cache) {
            return cache === 'hit' ? 'diag-chip cache-hit' : 'diag-chip cache-live';
        }

        function diagnosticStatusLabel(status) {
            switch (status) {
            case 'ok': return 'Hit';
            case 'not_found': return 'No Hit';
            case 'no_result': return 'No Hit';
            case 'no_results': return 'No Hit';
            case 'not_observed': return 'No Hit';
            case 'no_api_key': return 'No API Key';
            case 'parse_error': return 'Parse Error';
            case 'error': return 'Error';
            default: return status || 'Unknown';
            }
        }

        function diagnosticStatusClass(status) {
            switch (status) {
            case 'ok': return 'diag-chip status-ok';
            case 'not_found':
            case 'no_result':
            case 'no_results':
            case 'not_observed': return 'diag-chip status-miss';
            case 'no_api_key': return 'diag-chip status-muted';
            case 'parse_error':
            case 'error': return 'diag-chip status-error';
            default: return 'diag-chip status-muted';
            }
        }

        function hasThreatFoxHit(tf) {
            if (!tf) return false;
            return tf.queryStatus === 'ok';
        }

        function isThreatFoxMissStatus(status) {
            return status === 'no_result' || status === 'no_results' || status === 'not_found';
        }

        function showThreatFoxCard(tf) {
            if (!tf) return false;
            return tf.queryStatus === 'ok' || tf.queryStatus === 'error' || tf.queryStatus === 'parse_error';
        }

        function showMalwareBazaarCard(mb) {
            if (!mb) return false;
            return mb.queryStatus === 'ok' || mb.queryStatus === 'error' || mb.queryStatus === 'parse_error';
        }

        function showVirusTotalHashCard(result) {
            if (!result || !result.virustotal) return false;
            return !vtNotFound.value;
        }

        function showGreyNoiseCard(gn) {
            if (!gn) return false;
            if (gn.error) return true;
            return !gn.notObserved;
        }

        return {
            // State
            currentUser, isAdmin,
            ipInputText, hashInputText,
            ipUseCache, hashUseCache, isDragging,
            ipBulkCount, hashBulkCount,
            currentIOCMode, currentView, hashView, wideShell,
            allResults, activeIdx, allHashResults, activeHashIdx,
            isIPLoading, isHashLoading, ipError, hashError,
            scanHist, histDrawerOpen, colDrawerOpen,
            copyMenuOpen, hashCopyMenuOpen,
            tableSortCol, tableSortAsc, hashSortCol, hashSortAsc,
            colVisible, fieldVisible,
            // Computed
            colBadge,
            activeResultEntry, activeResultIP, activeResult,
            activeHashEntry, activeHashResult,
            hashResultLinks, signerDetailObj, signerIsRevoked, signerIsInvalid, signerIsValid, vtNotFound,
            networkRows, highlightedJSON, highlightedHashJSON,
            visibleTableCols, sortedTableRows,
            visibleHashTableCols, sortedHashRows,
            // Methods
            switchIOCMode, setView, setHashView, switchTab, switchToCard,
            riskDotColor, vtStatPart, abuseColor, formatBytes, toArr, yn,
            openColDrawer, closeColDrawer, toggleHistDrawer,
            clearHistory, reScan,
            goToSettings, goToAdmin, logoutNow,
            cacheHitLabels, hasCacheHits, diagnosticEntries,
            diagnosticCacheLabel, diagnosticCacheClass, diagnosticStatusLabel, diagnosticStatusClass,
            hasThreatFoxHit, isThreatFoxMissStatus, showThreatFoxCard, showMalwareBazaarCard, showVirusTotalHashCard, showGreyNoiseCard,
            doIPScan, doHashScanAction,
            handleIPFileUpload, handleIPDrop, clearIPBulk,
            handleHashFileUpload, clearHashBulk,
            copyJSON, copyHashJSON,
            toggleCopyMenu, toggleHashCopyMenu,
            copyClipboard, copyHashClipboard,
            exportCSV, exportJSON, exportHashCSV, exportHashJSON,
            sortTable, renderTableCell, sortHashTable, renderHashTableCell,
            // Domain
            allDomainResults, activeDomainIdx, activeDomainResult, activeDomainEntry,
            domainError, isDomainLoading, domainBulkCount, domainInputText, domainUseCache,
            domainView, domainResultLinks, highlightedDomainJSON,
            visibleDomainTableCols, sortedDomainRows, domainSortCol, domainSortAsc,
            sortDomainTable, renderDomainTableCell,
            copyDomainJSON, exportDomainCSV, exportDomainJSON,
            doDomainScan, setDomainView, clearDomainBulk, handleDomainFileUpload,
        };
    },

    template: `

  <!-- ══ TOPBAR ══════════════════════════════════════════════════════ -->
  <header class="site-header">

    <!-- Brand -->
    <div class="header-brand">
      <div class="brand-mark">
        <span class="brand-wordmark">
          <span class="text-t1">ioc</span><span class="text-prime">scan</span>
        </span>
      </div>
      <div class="brand-subcopy">
        <span class="brand-kicker">Threat Intelligence</span>
      </div>
    </div>

    <!-- Source badges -->
    <div class="header-sources-wrap">
      <div class="header-sources-label">Active Sources</div>
      <div class="header-sources">
        <span class="src-chip" style="color:#22d3ee;border-color:rgba(34,211,238,0.25)">VirusTotal</span>
        <span class="src-chip" style="color:#fb923c;border-color:rgba(251,146,60,0.25)">AbuseIPDB</span>
        <span class="src-chip" style="color:#4ade80;border-color:rgba(74,222,128,0.25)">ipapi.is</span>
        <span class="src-chip" style="color:#c084fc;border-color:rgba(192,132,252,0.25)">abuse.ch</span>
        <span class="src-chip" style="color:#fcd34d;border-color:rgba(252,211,77,0.25)">ThreatFox</span>
      </div>
    </div>

    <!-- Right actions -->
    <div class="header-actions">

      <!-- History -->
      <div class="header-action-group" style="position:relative">
        <button class="act-btn" @click="toggleHistDrawer">
          <span class="btn-glyph">⏱</span>
          History
          <span class="font-mono text-prime bg-prime/10 border border-prime/20 px-1.5 py-0 rounded text-xs">{{ scanHist.length }}</span>
        </button>
        <div class="hist-drawer" :class="{open: histDrawerOpen}">
          <div class="flex items-center justify-between px-4 py-3 border-b border-white/[0.06]">
            <span class="text-xs font-bold tracking-widest uppercase text-t2">History</span>
            <div class="flex gap-2">
              <button class="act-btn text-xs py-1" @click="clearHistory">Clear</button>
              <button class="act-btn text-xs py-1 px-2" @click="toggleHistDrawer">✕</button>
            </div>
          </div>
          <div class="overflow-y-auto flex-1">
            <p v-if="!scanHist.length" class="text-center py-5 text-t3 text-xs italic">No scans yet</p>
            <div v-for="(h,i) in scanHist" :key="h.ip+i" class="hist-item" @click="reScan(h.ip, h.iocType || 'ip')">
              <div class="flex items-center gap-2 min-w-0">
                <span class="font-mono text-xs text-t1 truncate">{{ h.ip }}</span>
                <span v-if="h.scanCount>1" class="text-t3 text-xs flex-shrink-0">×{{ h.scanCount }}</span>
              </div>
              <span :class="['t-risk','risk-'+h.risk]">{{ h.risk }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Columns -->
      <column-drawer></column-drawer>
      <div class="account-chip">
        <span class="account-dot"></span>
        <span class="account-name">{{ currentUser ? currentUser.username : '' }}</span>
      </div>
      <button class="act-btn" @click="goToSettings"><span class="btn-glyph">⚙</span>Settings</button>
      <button v-if="isAdmin" class="act-btn accent" @click="goToAdmin"><span class="btn-glyph">⌘</span>Admin</button>
      <button class="act-btn danger" @click="logoutNow"><span class="btn-glyph">↗</span>Logout</button>
    </div>
  </header>

  <!-- ══ PAGE BODY ══════════════════════════════════════════════════ -->
  <div class="px-8 py-8 pb-20" id="shell">

    <div class="keys-panel">
      <span class="keys-panel-label">API Keys</span>
      <div class="text-sm text-t2">
        API keys are managed in Settings for the signed-in account.
      </div>
    </div>

    <!-- Mode tabs -->
    <div class="flex border-b border-white/[0.08] mb-6">
      <button class="ioc-tab" :class="{active: currentIOCMode==='ip'}"   @click="switchIOCMode('ip')">IP Address</button>
      <button class="ioc-tab" :class="{active: currentIOCMode==='hash'}"   @click="switchIOCMode('hash')">File Hash</button>
      <button class="ioc-tab" :class="{active: currentIOCMode==='domain'}" @click="switchIOCMode('domain')">Domain</button>
    </div>

    <!-- ══ IP SECTION ══════════════════════════════════════════════ -->
    <div v-show="currentIOCMode==='ip'">

      <!-- Scan input -->
      <div class="scan-panel" :class="{'drag-over': isDragging}"
           @dragover.prevent="isDragging=true" @dragleave="isDragging=false" @drop.prevent="handleIPDrop">
        <div class="flex gap-3 items-stretch">
          <div class="flex-1 min-w-0">
            <textarea v-model="ipInputText" class="scan-input" rows="2"
              placeholder="8.8.8.8, 1.1.1.1 — paste IPs or drag a .txt / .csv file"
              @keydown.enter.exact.prevent="doIPScan"></textarea>
          </div>
          <div class="flex flex-col gap-2 flex-shrink-0 justify-start">
            <div class="flex items-center gap-2">
              <button class="scan-btn h-[46px]" :disabled="isIPLoading" @click="doIPScan">SCAN</button>
              <span v-if="isIPLoading" class="loader"></span>
            </div>
          </div>
        </div>
        <div class="flex items-center flex-wrap gap-2 mt-3">
          <div v-if="ipBulkCount" class="flex items-center gap-2 text-t2 text-xs">
            <span class="font-mono font-bold text-prime">{{ ipBulkCount }}</span> IPs detected
            <button class="meta-btn" @click="clearIPBulk">✕ Clear</button>
          </div>
          <label class="meta-btn cursor-pointer">
            ↑ Load File
            <input type="file" class="hidden" accept=".txt,.csv,.log" @change="handleIPFileUpload">
          </label>
          <div class="flex items-center gap-2 cursor-pointer ml-auto" @click="ipUseCache=!ipUseCache">
            <button class="tog" :class="{on: ipUseCache}"></button>
            <span class="text-xs text-t3 select-none">Cache</span>
          </div>
        </div>
      </div>

      <!-- Error -->
      <div v-if="ipError" class="err-box animate-fade-up">⚠ {{ ipError }}</div>

      <!-- Results -->
      <div v-if="allResults.length" id="ip-results-bar">

        <!-- Toolbar -->
        <div class="flex items-center flex-wrap gap-3 mb-5">
          <div class="view-toggle">
            <button class="view-btn" :class="{active: currentView==='cards'}" @click="setView('cards')">Cards</button>
            <button class="view-btn" :class="{active: currentView==='table'}" @click="setView('table')">Table</button>
          </div>
          <div class="flex items-center gap-2 ml-auto">
            <div class="copy-split copy-menu-w">
              <button class="act-btn copy-main" @click="toggleCopyMenu">⎘ Copy</button>
              <button class="act-btn copy-arr" @click="toggleCopyMenu">▾</button>
              <div class="copy-menu" :class="{open: copyMenuOpen}" @mouseleave="copyMenuOpen=false">
                <div class="copy-menu-item" @click="copyClipboard('json')">Copy as JSON</div>
                <div class="copy-menu-item" @click="copyClipboard('csv')">Copy as CSV</div>
                <div class="copy-menu-item" @click="copyClipboard('ips')">Copy IPs only</div>
              </div>
            </div>
            <button class="act-btn" @click="exportCSV">↓ CSV</button>
            <button class="act-btn" @click="exportJSON">↓ JSON</button>
          </div>
        </div>

        <!-- IP chip tabs -->
        <div v-if="allResults.length > 1 && currentView==='cards'" class="flex flex-wrap gap-2 mb-5">
          <div v-for="(r,i) in allResults" :key="r.ip"
               class="ip-tab" :class="{active: i===activeIdx}" @click="switchTab(i)">
            <span class="ip-tab-dot" :style="{background: riskDotColor(r.result ? r.result.riskLevel : null)}"></span>
            {{ r.ip }}
          </div>
        </div>

        <!-- ── CARDS VIEW ── -->
        <div v-show="currentView==='cards'">
          <div v-if="activeResult">

            <!-- Risk + IP -->
            <div v-if="colVisible.risk" class="flex items-center gap-3 mb-5 flex-wrap animate-fade-up">
              <span :class="['risk-pill','risk-'+(activeResult.riskLevel||'CLEAN')]">
                <span class="risk-dot"></span>
                {{ activeResult.riskLevel || 'CLEAN' }}
              </span>
              <span class="font-mono text-lg text-t1">{{ activeResultIP }}</span>
              <span v-if="activeResultEntry && activeResultEntry.error"
                    class="text-xs text-rm border border-rm/25 px-2 py-0.5 rounded-pill">⚠ partial</span>
            </div>
            <div v-if="hasCacheHits(activeResult)" class="flex items-center gap-2 mb-5 flex-wrap animate-fade-up">
              <span class="text-[11px] uppercase tracking-[0.16em] text-t3">Cache Hit</span>
              <span v-for="label in cacheHitLabels(activeResult)" :key="label"
                    class="text-xs px-2 py-0.5 border rounded-pill text-prime border-prime/20 bg-prime/10">
                {{ label }}
              </span>
              <span v-if="activeResult.cached" class="text-xs px-2 py-0.5 border rounded-pill text-[#7ee0a0] border-[#7ee0a0]/20 bg-[#7ee0a0]/10">
                All Cached
              </span>
            </div>
            <details v-if="diagnosticEntries(activeResult).length" class="diag-panel mb-5">
              <summary class="diag-summary">
                <span>Diagnostics</span>
                <span class="diag-summary-meta">{{ diagnosticEntries(activeResult).length }} sources</span>
              </summary>
              <div class="diag-grid">
                <div v-for="entry in diagnosticEntries(activeResult)" :key="'ip-diag-'+entry.key"
                     class="diag-row">
                  <div class="diag-source">
                    <span class="diag-source-name">{{ entry.label }}</span>
                    <span class="diag-source-key">{{ entry.key }}</span>
                  </div>
                  <div class="diag-badges">
                    <span :class="diagnosticCacheClass(entry.cache)">{{ diagnosticCacheLabel(entry.cache) }}</span>
                    <span :class="diagnosticStatusClass(entry.status)">{{ diagnosticStatusLabel(entry.status) }}</span>
                    <span v-if="entry.error" class="diag-chip status-error max-w-[28rem] truncate" :title="entry.error">{{ entry.error }}</span>
                  </div>
                </div>
              </div>
            </details>

            <!-- Cards grid -->
            <div class="grid gap-3 mb-4" style="grid-template-columns:repeat(auto-fill,minmax(290px,1fr))">

              <!-- Network -->
              <div v-if="colVisible.network && networkRows.length" class="vcard animate-fade-up">
                <div class="vcard-head">
                  <span class="vcard-title">🌍 Network</span>
                  <a :href="'https://api.ipapi.is/?q='+activeResultIP" target="_blank" rel="noopener" class="vcard-link">↗ ipapi.is</a>
                </div>
                <div class="vcard-body">
                  <div v-for="[k,v,fkey] in networkRows" :key="k" class="kv" :data-field="fkey" v-show="!fkey||fieldVisible[fkey]">
                    <span class="kv-key">{{ k }}</span>
                    <span class="kv-val" v-html="v"></span>
                  </div>
                </div>
              </div>

              <!-- AbuseIPDB -->
              <div v-if="colVisible.abuse && activeResult.abuseipdb && activeResult.abuseipdb.confidenceScore!=null && !activeResult.abuseipdb.error"
                   class="vcard animate-fade-up-2">
                <div class="vcard-head">
                  <span class="vcard-title">🚨 AbuseIPDB</span>
                  <a :href="'https://www.abuseipdb.com/check/'+activeResultIP" target="_blank" rel="noopener" class="vcard-link">↗ AbuseIPDB</a>
                </div>
                <div class="vcard-body">
                  <div class="kv" v-show="fieldVisible['ab-score']">
                    <span class="kv-key">Confidence</span>
                    <span class="kv-val font-bold" :style="{color: abuseColor(activeResult.abuseipdb.confidenceScore)}">
                      {{ activeResult.abuseipdb.confidenceScore }}%
                    </span>
                  </div>
                  <div class="meter" v-show="fieldVisible['ab-meter']">
                    <div class="meter-bar" :style="{width: activeResult.abuseipdb.confidenceScore+'%', background: abuseColor(activeResult.abuseipdb.confidenceScore)}"></div>
                  </div>
                  <div class="kv" v-show="fieldVisible['ab-reports']">
                    <span class="kv-key">Reports</span>
                    <span class="kv-val">{{ activeResult.abuseipdb.totalReports ?? '—' }}</span>
                  </div>
                  <div class="kv" v-show="fieldVisible['ab-lastreport']">
                    <span class="kv-key">Last Reported</span>
                    <span class="kv-val">{{ activeResult.abuseipdb.lastReportedAt || '—' }}</span>
                  </div>
                  <div v-if="activeResult.abuseipdb.usageType" class="kv">
                    <span class="kv-key">Usage Type</span>
                    <span class="kv-val">{{ activeResult.abuseipdb.usageType }}</span>
                  </div>
                  <div v-if="activeResult.abuseipdb.domain" class="kv">
                    <span class="kv-key">Domain</span>
                    <span class="kv-val">{{ activeResult.abuseipdb.domain }}</span>
                  </div>
                  <div v-if="activeResult.abuseipdb.numDistinctUsers" class="kv">
                    <span class="kv-key">Distinct Users</span>
                    <span class="kv-val">{{ activeResult.abuseipdb.numDistinctUsers }}</span>
                  </div>
                  <div class="kv">
                    <span class="kv-key">Tor Exit Node</span>
                    <span class="kv-val font-semibold" :style="{color: activeResult.abuseipdb.isTor ? 'var(--r0)' : 'var(--r4)'}">
                      {{ activeResult.abuseipdb.isTor ? '✓ Yes' : '✗ No' }}
                    </span>
                  </div>
                  <div class="kv">
                    <span class="kv-key">Public IP</span>
                    <span class="kv-val font-semibold" :style="{color: activeResult.abuseipdb.isPublic ? 'var(--r3)' : 'var(--r4)'}">
                      {{ activeResult.abuseipdb.isPublic ? '✓ Yes' : '✗ No' }}
                    </span>
                  </div>
                  <div class="kv">
                    <span class="kv-key">Whitelisted</span>
                    <span class="kv-val font-semibold" :style="{color: activeResult.abuseipdb.isWhitelisted ? 'var(--r4)' : 'var(--r3)'}">
                      {{ activeResult.abuseipdb.isWhitelisted ? '✓ Yes' : '✗ No' }}
                    </span>
                  </div>
                  <div v-if="activeResult.abuseipdb.hostnames && activeResult.abuseipdb.hostnames.length" class="kv" style="align-items:flex-start">
                    <span class="kv-key" style="padding-top:2px">Hostnames</span>
                    <span class="kv-val text-right" style="font-size:0.65rem">
                      {{ activeResult.abuseipdb.hostnames.join(', ') }}
                    </span>
                  </div>
                  <div v-if="activeResult.abuseipdb.categories && activeResult.abuseipdb.categories.length"
                       class="border-t border-white/6 px-3 pt-2 pb-3">
                    <div class="text-xs font-bold tracking-widest uppercase mb-1.5" style="color:#565e6e;font-size:0.54rem">Report Categories</div>
                    <div class="flex flex-wrap gap-1">
                      <span v-for="cat in activeResult.abuseipdb.categories" :key="cat"
                            class="text-xs px-2 py-0.5 border rounded font-medium"
                            style="color:#fba962;border-color:rgba(251,169,98,0.28);background:rgba(251,169,98,0.08);font-size:0.6rem">
                        {{ cat }}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              <!-- VirusTotal -->
              <div v-if="colVisible.vt && activeResult.virustotal && activeResult.virustotal.malicious!=null && !activeResult.virustotal.error"
                   class="vcard animate-fade-up-3">
                <div class="vcard-head">
                  <span class="vcard-title">🧪 VirusTotal</span>
                  <a :href="'https://www.virustotal.com/gui/ip-address/'+activeResultIP" target="_blank" rel="noopener" class="vcard-link">↗ VirusTotal</a>
                </div>
                <div class="vcard-body">
                  <div class="kv" v-show="fieldVisible['vt-summary']">
                    <span class="kv-key">S / U / H</span>
                    <span class="kv-val">{{ activeResult.virustotal ? (activeResult.virustotal.suspicious??0)+' / '+(activeResult.virustotal.undetected??0)+' / '+(activeResult.virustotal.harmless??0) : '—' }}</span>
                  </div>
                  <div class="vt-pills">
                    <span v-show="fieldVisible['vt-malicious']"  class="vt-pill mal">Malicious · {{ activeResult.virustotal.malicious }}</span>
                    <span v-show="fieldVisible['vt-suspicious']" class="vt-pill sus">Suspicious · {{ activeResult.virustotal.suspicious??0 }}</span>
                    <span v-show="fieldVisible['vt-harmless']"   class="vt-pill ok">Harmless · {{ vtStatPart(2) }}</span>
                    <span v-show="fieldVisible['vt-undetected']" class="vt-pill unk">Undetected · {{ vtStatPart(1) }}</span>
                  </div>
                  <div v-if="activeResult.virustotal.lastAnalysisDate"
                       class="kv border-t border-white/6 px-3 py-2">
                    <span class="kv-key">Last Scanned</span>
                    <span class="kv-val" style="color:#9ca3b0">{{ activeResult.virustotal.lastAnalysisDate }}</span>
                  </div>
                </div>
              </div>

              <!-- ThreatFox -->
              <div v-if="showThreatFoxCard(activeResult.threatfox)" class="vcard animate-fade-up-4">
                <div class="vcard-head">
                  <span class="vcard-title">🦊 ThreatFox</span>
                  <div class="flex items-center gap-2">
                    <span v-if="hasThreatFoxHit(activeResult.threatfox)" class="mb-found-badge">✓ Found</span>
                    <span v-else class="mb-notfound-badge">{{ activeResult.threatfox.queryStatus || 'No result' }}</span>
                    <a :href="'https://threatfox.abuse.ch/browse.php?search=ioc%3A'+activeResultIP" target="_blank" rel="noopener" class="vcard-link">↗ ThreatFox</a>
                  </div>
                </div>
                <div class="vcard-body">
                  <template v-if="activeResult.threatfox.queryStatus==='ok'">
                    <div v-if="activeResult.threatfox.malware" class="kv">
                      <span class="kv-key">Malware</span>
                      <span class="kv-val font-bold" style="color:var(--r0)">{{ activeResult.threatfox.malware }}</span>
                    </div>
                    <div v-if="activeResult.threatfox.threatType" class="kv">
                      <span class="kv-key">Threat Type</span>
                      <span class="kv-val">{{ activeResult.threatfox.threatType }}</span>
                    </div>
                    <div v-if="activeResult.threatfox.malwareAlias" class="kv">
                      <span class="kv-key">Aliases</span>
                      <span class="kv-val text-t2" style="font-size:0.64rem">{{ activeResult.threatfox.malwareAlias }}</span>
                    </div>
                    <div v-if="activeResult.threatfox.confidenceLevel!=null" class="kv">
                      <span class="kv-key">Confidence</span>
                      <span class="kv-val font-bold" :style="{color:activeResult.threatfox.confidenceLevel>=75?'var(--r0)':activeResult.threatfox.confidenceLevel>=50?'var(--r1)':'var(--r2)'}">
                        {{ activeResult.threatfox.confidenceLevel }}%
                      </span>
                    </div>
                    <div v-if="activeResult.threatfox.firstSeen" class="kv">
                      <span class="kv-key">First Seen</span>
                      <span class="kv-val">{{ activeResult.threatfox.firstSeen }}</span>
                    </div>
                    <div v-if="activeResult.threatfox.reporter" class="kv">
                      <span class="kv-key">Reporter</span>
                      <span class="kv-val text-t2">{{ activeResult.threatfox.reporter }}</span>
                    </div>
                    <div v-if="activeResult.threatfox.tags && activeResult.threatfox.tags.length" class="px-3 pb-3 pt-1 flex flex-wrap gap-1">
                      <span v-for="tag in activeResult.threatfox.tags" :key="tag" class="hash-tag">{{ tag }}</span>
                    </div>
                    <div v-if="activeResult.threatfox.malwareSamples && activeResult.threatfox.malwareSamples.length" class="px-3 pb-3">
                      <div class="vt-subsection-label">Associated Samples</div>
                      <div v-for="s in activeResult.threatfox.malwareSamples" :key="s.sha256_hash" class="kv" style="align-items:flex-start;padding:4px 0">
                        <span class="kv-key" style="font-size:0.56rem;padding-top:2px">SHA256</span>
                        <span class="kv-val" style="font-size:0.56rem;word-break:break-all">
                          <a v-if="s.malware_bazaar" :href="s.malware_bazaar" target="_blank" rel="noopener" class="text-prime">{{ s.sha256_hash }}</a>
                          <span v-else>{{ s.sha256_hash }}</span>
                        </span>
                      </div>
                    </div>
                  </template>
                  <div v-if="activeResult.threatfox.queryStatus!=='ok'" class="kv">
                    <span class="kv-val text-t3 italic" style="font-size:0.66rem">
                      {{ isThreatFoxMissStatus(activeResult.threatfox.queryStatus) ? 'No ThreatFox intelligence for this IP.' : activeResult.threatfox.queryStatus }}
                    </span>
                  </div>
                </div>
              </div>

              <!-- GreyNoise -->
              <div v-if="showGreyNoiseCard(activeResult.greynoise)" class="vcard" style="animation:fadeUp 0.22s ease 0.20s both">
                <div class="vcard-head">
                  <span class="vcard-title">🔊 GreyNoise</span>
                  <div class="flex items-center gap-2">
                    <span v-if="activeResult.greynoise.classification==='malicious'" class="mb-found-badge" style="color:var(--r0);border-color:rgba(252,129,129,0.3);background:var(--r0a)">✗ Malicious</span>
                    <span v-else-if="activeResult.greynoise.classification==='benign'" class="mb-found-badge">✓ Benign</span>
                    <span v-else-if="activeResult.greynoise.noise" class="mb-notfound-badge" style="color:var(--r2);border-color:rgba(252,211,77,0.3)">⚡ Noise</span>
                    <span v-else-if="activeResult.greynoise.error" class="mb-notfound-badge">No result</span>
                    <a :href="'https://viz.greynoise.io/ip/'+activeResultIP" target="_blank" rel="noopener" class="vcard-link">↗ GreyNoise</a>
                  </div>
                </div>
                <div class="vcard-body">
                  <div v-if="activeResult.greynoise.error" class="kv">
                    <span class="kv-val text-t3 italic" style="font-size:0.66rem">{{ activeResult.greynoise.error }}</span>
                  </div>
                  <template v-else>
                    <div v-if="activeResult.greynoise.classification" class="kv">
                      <span class="kv-key">Classification</span>
                      <span class="kv-val font-semibold"
                            :style="{color: activeResult.greynoise.classification==='malicious'?'var(--r0)':activeResult.greynoise.classification==='benign'?'var(--r4)':'var(--r2)'}">
                        {{ activeResult.greynoise.classification }}
                      </span>
                    </div>
                    <div v-if="activeResult.greynoise.name && activeResult.greynoise.name !== 'unknown'" class="kv">
                      <span class="kv-key">Actor</span>
                      <span class="kv-val">{{ activeResult.greynoise.name }}</span>
                    </div>
                    <div class="kv">
                      <span class="kv-key">Internet Scanner</span>
                      <span class="kv-val font-semibold" :style="{color: activeResult.greynoise.noise?'var(--r2)':'var(--r4)'}">
                        {{ activeResult.greynoise.noise ? '✓ Yes' : '✗ No' }}
                      </span>
                    </div>
                    <div class="kv">
                      <span class="kv-key">RIOT (trusted)</span>
                      <span class="kv-val font-semibold" :style="{color: activeResult.greynoise.riot?'var(--r4)':'var(--t3)'}">
                        {{ activeResult.greynoise.riot ? '✓ Yes' : '✗ No' }}
                      </span>
                    </div>
                    <div v-if="activeResult.greynoise.lastSeen" class="kv">
                      <span class="kv-key">Last Seen</span>
                      <span class="kv-val">{{ activeResult.greynoise.lastSeen }}</span>
                    </div>
                  </template>
                </div>
              </div>

            </div><!-- /grid -->

            <!-- JSON panel -->
            <div v-if="colVisible.json" class="json-panel animate-fade-up">
              <button class="hash-source-link float-right mb-2" @click="copyJSON">COPY</button>
              <pre><code v-html="highlightedJSON"></code></pre>
            </div>
          </div>

          <div v-else-if="activeResultEntry && activeResultEntry.error" class="vcard animate-fade-up">
            <div class="vcard-head"><span class="vcard-title">Error</span></div>
            <div class="kv"><span class="kv-val" style="color:var(--r0)">{{ activeResultEntry.error }}</span></div>
          </div>
        </div>

        <!-- ── TABLE VIEW ── -->
        <div v-show="currentView==='table'">
          <results-table
            :visible-cols="visibleTableCols" :sorted-rows="sortedTableRows"
            :sort-col="tableSortCol" :sort-asc="tableSortAsc"
            :render-cell="renderTableCell"
            @sort="sortTable" @row-click="row => switchToCard(row._idx)">
          </results-table>
        </div>
      </div>
    </div>

    <!-- ══ HASH SECTION ══════════════════════════════════════════════ -->
    <div v-show="currentIOCMode==='hash'">

      <!-- Scan input -->
      <div class="scan-panel">
        <div class="flex gap-3 items-stretch">
          <textarea v-model="hashInputText" class="scan-input flex-1" rows="3"
            placeholder="Paste MD5, SHA1, or SHA256 hashes — one per line"
            @keydown.enter.exact.prevent="doHashScanAction"></textarea>
          <div class="flex flex-col gap-2 flex-shrink-0 justify-start">
            <div class="flex items-center gap-2">
              <button class="scan-btn h-[46px]" :disabled="isHashLoading" @click="doHashScanAction">SCAN</button>
              <span v-if="isHashLoading" class="loader"></span>
            </div>
          </div>
        </div>
        <div class="flex items-center flex-wrap gap-2 mt-3">
          <div v-if="hashBulkCount" class="flex items-center gap-2 text-t2 text-xs">
            <span class="font-mono font-bold text-prime">{{ hashBulkCount }}</span> hashes detected
            <button class="meta-btn" @click="clearHashBulk">✕ Clear</button>
          </div>
          <label class="meta-btn cursor-pointer">
            ↑ Load File
            <input type="file" class="hidden" accept=".txt,.csv,.log" @change="handleHashFileUpload">
          </label>
          <div class="flex items-center gap-2 cursor-pointer ml-auto" @click="hashUseCache=!hashUseCache">
            <button class="tog" :class="{on: hashUseCache}"></button>
            <span class="text-xs text-t3 select-none">Cache</span>
          </div>
        </div>
      </div>

      <div v-if="hashError" class="err-box animate-fade-up">⚠ {{ hashError }}</div>

      <div v-if="allHashResults.length">
        <!-- Toolbar -->
        <div id="hash-results-bar" class="flex items-center flex-wrap gap-3 mb-5">
          <div class="view-toggle">
            <button class="view-btn" :class="{active: hashView==='cards'}" @click="setHashView('cards')">Cards</button>
            <button class="view-btn" :class="{active: hashView==='table'}" @click="setHashView('table')">Table</button>
          </div>
          <div class="flex items-center gap-2 ml-auto">
            <div class="copy-split copy-menu-w" style="position:relative">
              <button class="act-btn copy-main" id="hashClipboardBtn" @click="copyHashClipboard('json')">⎘ Copy</button>
              <button class="act-btn copy-arr" @click="toggleHashCopyMenu">▾</button>
              <div class="copy-menu" :class="{open: hashCopyMenuOpen}" @mouseleave="hashCopyMenuOpen=false">
                <div class="copy-menu-item" @click="copyHashClipboard('json')">Copy as JSON</div>
                <div class="copy-menu-item" @click="copyHashClipboard('csv')">Copy as CSV</div>
                <div class="copy-menu-item" @click="copyHashClipboard('hashes')">Copy hashes only</div>
              </div>
            </div>
            <button class="act-btn" @click="exportHashCSV">↓ CSV</button>
            <button class="act-btn" @click="exportHashJSON">↓ JSON</button>
          </div>
        </div>

        <!-- Hash chip tabs -->
        <div v-if="allHashResults.length > 1 && hashView==='cards'" class="flex flex-wrap gap-2 mb-5">
          <div v-for="(e,i) in allHashResults" :key="i"
               class="ip-tab" :class="{active: i===activeHashIdx}" @click="activeHashIdx=i">
            <span class="ip-tab-dot" :style="{background: riskDotColor((e.result||e).riskLevel)}"></span>
            {{ ((e.result||e).virustotal?.sha256||(e.result||e).virustotal?.sha1||(e.result||e).virustotal?.md5||e.hash||'?').slice(0,14) }}…
          </div>
        </div>

        <!-- ── HASH CARDS ── -->
        <div v-show="hashView==='cards'">
          <div v-if="activeHashResult">

            <div class="hash-card animate-fade-up"
                 :class="'hash-card-top-'+(activeHashResult.riskLevel||'').toLowerCase()">

              <!-- Header -->
              <div class="flex items-start justify-between gap-4 p-5 border-b border-white/[0.06]"
                   style="background:#15151c">
                <div class="flex-1 min-w-0">
                  <div class="font-mono text-xs text-t1 break-all leading-relaxed mb-2">
                    {{ (activeHashResult.virustotal&&(activeHashResult.virustotal.sha256||activeHashResult.virustotal.sha1||activeHashResult.virustotal.md5))||allHashResults[activeHashIdx]?.hash||'—' }}
                  </div>
                  <div class="flex flex-wrap gap-1.5">
                    <span v-if="activeHashResult.riskLevel" :class="['risk-pill','risk-'+activeHashResult.riskLevel]">
                      <span class="risk-dot"></span>{{ activeHashResult.riskLevel }}
                    </span>
                    <span v-if="activeHashResult.hashType" class="hash-type-badge">{{ activeHashResult.hashType }}</span>
                    <span v-if="activeHashResult.virustotal&&activeHashResult.virustotal.suggestedThreatLabel" class="hash-threat-label">{{ activeHashResult.virustotal.suggestedThreatLabel }}</span>
                    <span v-for="label in cacheHitLabels(activeHashResult)" :key="'hash-cache-'+label"
                          class="text-xs px-2 py-0.5 border rounded-pill text-prime border-prime/20 bg-prime/10">
                      Cache: {{ label }}
                    </span>
                    <span v-if="activeHashResult.cached" class="text-xs px-2 py-0.5 border rounded-pill text-[#7ee0a0] border-[#7ee0a0]/20 bg-[#7ee0a0]/10">
                      All Cached
                    </span>
                  </div>
                  <details v-if="diagnosticEntries(activeHashResult).length" class="diag-panel mt-3">
                    <summary class="diag-summary">
                      <span>Diagnostics</span>
                      <span class="diag-summary-meta">{{ diagnosticEntries(activeHashResult).length }} sources</span>
                    </summary>
                    <div class="diag-grid">
                      <div v-for="entry in diagnosticEntries(activeHashResult)" :key="'hash-diag-'+entry.key"
                           class="diag-row">
                        <div class="diag-source">
                          <span class="diag-source-name">{{ entry.label }}</span>
                          <span class="diag-source-key">{{ entry.key }}</span>
                        </div>
                        <div class="diag-badges">
                          <span :class="diagnosticCacheClass(entry.cache)">{{ diagnosticCacheLabel(entry.cache) }}</span>
                          <span :class="diagnosticStatusClass(entry.status)">{{ diagnosticStatusLabel(entry.status) }}</span>
                          <span v-if="entry.error" class="diag-chip status-error max-w-[24rem] truncate" :title="entry.error">{{ entry.error }}</span>
                        </div>
                      </div>
                    </div>
                  </details>
                </div>
                <div class="flex gap-2 flex-shrink-0">
                  <a v-if="hashResultLinks.virustotal && !vtNotFound" :href="hashResultLinks.virustotal" target="_blank" rel="noopener" class="hash-source-link">↗ VT</a>
                  <span v-else-if="vtNotFound" class="hash-source-link-na">✗ VT</span>
                  <a v-if="hashResultLinks.malwarebazaar && activeHashResult.malwarebazaar && activeHashResult.malwarebazaar.queryStatus==='ok'" :href="hashResultLinks.malwarebazaar" target="_blank" rel="noopener" class="hash-source-link">↗ MB</a>
                  <span v-else-if="activeHashResult.malwarebazaar && activeHashResult.malwarebazaar.queryStatus && activeHashResult.malwarebazaar.queryStatus!=='ok'" class="hash-source-link-na">✗ MB</span>
                </div>
              </div>

              <!-- Hash values -->
              <div class="px-5 py-3 border-b border-white/[0.06]">
                <div class="hash-section-title">Hash Values</div>
                <div v-if="activeHashResult.virustotal?.md5"    class="hash-kv"><span class="hash-kv-key">MD5</span><span class="hash-kv-val">{{ activeHashResult.virustotal.md5 }}</span></div>
                <div v-if="activeHashResult.virustotal?.sha1"   class="hash-kv"><span class="hash-kv-key">SHA1</span><span class="hash-kv-val">{{ activeHashResult.virustotal.sha1 }}</span></div>
                <div v-if="activeHashResult.virustotal?.sha256" class="hash-kv"><span class="hash-kv-key">SHA256</span><span class="hash-kv-val">{{ activeHashResult.virustotal.sha256 }}</span></div>
              </div>

              <!-- Sub-card grid -->
              <div class="p-4 grid gap-3" style="grid-template-columns:repeat(auto-fill,minmax(260px,1fr))">

                <!-- File info -->
                <div class="vcard">
                  <div class="vcard-head"><span class="vcard-title">📄 File Info</span></div>
                  <div class="vcard-body">
                    <div v-if="activeHashResult.virustotal?.meaningfulName" class="hash-kv px-3"><span class="hash-kv-key">Name</span><span class="hash-kv-val">{{ activeHashResult.virustotal.meaningfulName }}</span></div>
                    <div v-if="activeHashResult.virustotal?.magic"           class="hash-kv px-3"><span class="hash-kv-key">Type</span><span class="hash-kv-val">{{ activeHashResult.virustotal.magic }}</span></div>
                    <div v-if="activeHashResult.virustotal?.magika"          class="hash-kv px-3"><span class="hash-kv-key">Magika</span><span class="hash-kv-val">{{ activeHashResult.virustotal.magika }}</span></div>
                    <div v-if="activeHashResult.virustotal?.fileSize"        class="hash-kv px-3"><span class="hash-kv-key">Size</span><span class="hash-kv-val">{{ formatBytes(activeHashResult.virustotal.fileSize) }}</span></div>
                    <div v-if="activeHashResult.virustotal && toArr(activeHashResult.virustotal.signatureSigners).length" class="hash-kv px-3">
                      <span class="hash-kv-key">Signer</span>
                      <span class="hash-kv-val">{{ toArr(activeHashResult.virustotal.signatureSigners).join(', ') }}</span>
                    </div>
                    <div v-if="activeHashResult.virustotal && toArr(activeHashResult.virustotal.signatureSigners).length"
                         class="mx-3 mb-2 codesign-box"
                         :class="{'codesign-box-valid': signerIsValid, 'codesign-box-warn': signerIsInvalid, 'codesign-box-danger': signerIsRevoked}">
                      <div class="codesign-revoked" :class="{'codesign-head-valid': signerIsValid, 'codesign-head-warn': signerIsInvalid}">
                        Code Signed
                        <span v-if="signerIsRevoked" class="revoked-badge">REVOKED</span>
                        <span v-else-if="signerIsValid" class="valid-badge">VALID</span>
                        <span v-else-if="signerIsInvalid" class="invalid-badge">INVALID</span>
                      </div>
                      <template v-if="signerDetailObj">
                        <div class="codesign-row"><span class="codesign-lbl">Issuer</span><span class="codesign-val">{{ signerDetailObj.certIssuer }}</span></div>
                        <div class="codesign-row"><span class="codesign-lbl">Entity</span><span class="codesign-val">{{ signerDetailObj.name }}</span></div>
                        <div v-if="signerDetailObj.validFrom" class="codesign-row"><span class="codesign-lbl">Valid</span><span class="codesign-val">{{ signerDetailObj.validFrom }} → {{ signerDetailObj.validTo }}</span></div>
                        <div class="codesign-status" :class="{'codesign-status-valid': signerIsValid, 'codesign-status-warn': signerIsInvalid}">{{ signerDetailObj.status }}</div>
                      </template>
                    </div>
                  </div>
                </div>

                <!-- VirusTotal hash -->
                <div v-if="showVirusTotalHashCard(activeHashResult)" class="vcard">
                  <div class="vcard-head">
                    <span class="vcard-title">🧪 VirusTotal</span>
                    <span v-if="vtNotFound" class="mb-notfound-badge">Not Found</span>
                  </div>
                  <div class="vcard-body">
                    <div v-if="vtNotFound" class="kv"><span class="kv-val text-t3 italic" style="font-size:0.66rem">Not indexed in VirusTotal.</span></div>
                    <template v-else-if="activeHashResult.virustotal">
                      <div class="vt-pills">
                        <span class="vt-badge mal">Malicious · {{ activeHashResult.virustotal.malicious }}</span>
                        <span class="vt-badge sus">Suspicious · {{ activeHashResult.virustotal.suspicious??0 }}</span>
                        <span v-if="activeHashResult.virustotal.harmless!=null"   class="vt-badge ok">Harmless · {{ activeHashResult.virustotal.harmless }}</span>
                        <span v-if="activeHashResult.virustotal.undetected!=null" class="vt-badge unk">Undetected · {{ activeHashResult.virustotal.undetected }}</span>
                      </div>
                      <div v-if="activeHashResult.virustotal.reputation!=null" class="kv">
                        <span class="kv-key">Reputation</span>
                        <span class="kv-val font-bold" :style="{color:activeHashResult.virustotal.reputation<0?'var(--r0)':activeHashResult.virustotal.reputation>0?'var(--r4)':'#565e6e'}">
                          {{ activeHashResult.virustotal.reputation>0?'+':'' }}{{ activeHashResult.virustotal.reputation }}
                        </span>
                      </div>
                      <div v-if="activeHashResult.virustotal.lastAnalysisDate" class="kv">
                        <span class="kv-key">Last Scanned</span>
                        <span class="kv-val" style="color:#9ca3b0">{{ activeHashResult.virustotal.lastAnalysisDate }}</span>
                      </div>
                      <div v-if="toArr(activeHashResult.virustotal.popularThreatNames).length" class="px-3 pb-2">
                        <div class="vt-subsection-label">Threat Names</div>
                        <div class="flex flex-wrap gap-1 mt-1">
                          <span v-for="n in toArr(activeHashResult.virustotal.popularThreatNames)" :key="n" class="hash-family-badge">{{ n }}</span>
                        </div>
                      </div>
                      <div v-if="toArr(activeHashResult.virustotal.popularThreatCategories).length" class="px-3 pb-2">
                        <div class="vt-subsection-label">Categories</div>
                        <div class="flex flex-wrap gap-1 mt-1">
                          <span v-for="c in toArr(activeHashResult.virustotal.popularThreatCategories)" :key="c" class="hash-category-badge">{{ c }}</span>
                        </div>
                      </div>
                      <div v-if="toArr(activeHashResult.virustotal.sandboxMalwareClassifications).length" class="px-3 pb-2">
                        <div class="vt-subsection-label">Sandbox</div>
                        <div class="flex flex-wrap gap-1 mt-1">
                          <span v-for="s in toArr(activeHashResult.virustotal.sandboxMalwareClassifications)" :key="s" class="sandbox-badge">{{ s }}</span>
                        </div>
                      </div>
                      <div v-if="activeHashResult.virustotal.sigmaAnalysisSummary && Object.keys(activeHashResult.virustotal.sigmaAnalysisSummary).length" class="px-3 pb-2">
                        <div class="vt-subsection-label">Sigma Rules</div>
                        <div v-for="(counts,ruleset) in activeHashResult.virustotal.sigmaAnalysisSummary" :key="ruleset" class="sigma-block">
                          <div class="sigma-ruleset">{{ ruleset }}</div>
                          <div class="flex flex-wrap gap-1">
                            <span v-if="counts.critical" class="sigma-pill critical">Critical · {{ counts.critical }}</span>
                            <span v-if="counts.high"     class="sigma-pill high">High · {{ counts.high }}</span>
                            <span v-if="counts.medium"   class="sigma-pill medium">Medium · {{ counts.medium }}</span>
                            <span v-if="counts.low"      class="sigma-pill low">Low · {{ counts.low }}</span>
                          </div>
                        </div>
                      </div>
                    </template>
                  </div>
                </div>

                <!-- MalwareBazaar -->
                <div v-if="showMalwareBazaarCard(activeHashResult.malwarebazaar)" class="vcard">
                  <div class="vcard-head">
                    <span class="vcard-title">🦠 MalwareBazaar</span>
                    <div class="flex items-center gap-2">
                      <span v-if="activeHashResult.malwarebazaar.queryStatus==='ok'" class="mb-found-badge">✓ Found</span>
                      <span v-else class="mb-notfound-badge">{{ activeHashResult.malwarebazaar.queryStatus }}</span>
                    </div>
                  </div>
                  <div class="vcard-body">
                    <template v-if="activeHashResult.malwarebazaar.queryStatus==='ok'">
                      <div v-if="activeHashResult.malwarebazaar.signature" class="kv">
                        <span class="kv-key">Signature</span>
                        <span class="kv-val font-bold" style="color:var(--r0)">{{ activeHashResult.malwarebazaar.signature }}</span>
                      </div>
                      <div v-if="activeHashResult.malwarebazaar.fileName" class="kv">
                        <span class="kv-key">File Name</span><span class="kv-val">{{ activeHashResult.malwarebazaar.fileName }}</span>
                      </div>
                      <div v-if="activeHashResult.malwarebazaar.fileType" class="kv">
                        <span class="kv-key">File Type</span>
                        <span class="kv-val"><span class="filetype-badge">{{ activeHashResult.malwarebazaar.fileType }}</span></span>
                      </div>
                      <div v-if="activeHashResult.malwarebazaar.comment" class="kv" style="align-items:flex-start">
                        <span class="kv-key" style="padding-top:2px">Comment</span>
                        <span class="kv-val mb-comment">{{ activeHashResult.malwarebazaar.comment }}</span>
                      </div>
                      <div v-if="toArr(activeHashResult.malwarebazaar.tags).length" class="px-3 pb-3 pt-1 flex flex-wrap gap-1">
                        <span v-for="tag in toArr(activeHashResult.malwarebazaar.tags)" :key="tag" class="hash-tag">{{ tag }}</span>
                      </div>
                    </template>
                    <div v-else class="kv">
                      <span class="kv-val text-t3 italic" style="font-size:0.66rem">
                        {{ activeHashResult.malwarebazaar.queryStatus==='hash_not_found'?'Not indexed in MalwareBazaar.':activeHashResult.malwarebazaar.queryStatus }}
                      </span>
                    </div>
                  </div>
                </div>

                <!-- ThreatFox hash -->
                <div v-if="showThreatFoxCard(activeHashResult.threatfox)" class="vcard">
                  <div class="vcard-head">
                    <span class="vcard-title">🦊 ThreatFox</span>
                    <span v-if="hasThreatFoxHit(activeHashResult.threatfox)" class="mb-found-badge">✓ Found</span>
                    <span v-else class="mb-notfound-badge">{{ activeHashResult.threatfox.queryStatus||'No result' }}</span>
                  </div>
                  <div class="vcard-body">
                    <template v-if="activeHashResult.threatfox.queryStatus==='ok' && activeHashResult.threatfox.iocs?.length">
                      <div v-if="activeHashResult.threatfox.iocs[0].malware" class="kv">
                        <span class="kv-key">Malware</span>
                        <span class="kv-val font-bold" style="color:var(--r0)">{{ activeHashResult.threatfox.iocs[0].malware }}</span>
                      </div>
                      <div v-if="activeHashResult.threatfox.iocs[0].threatType" class="kv">
                        <span class="kv-key">Threat Type</span><span class="kv-val">{{ activeHashResult.threatfox.iocs[0].threatType }}</span>
                      </div>
                      <div v-if="activeHashResult.threatfox.iocs[0].confidenceLevel!=null" class="kv">
                        <span class="kv-key">Confidence</span>
                        <span class="kv-val font-bold" :style="{color:activeHashResult.threatfox.iocs[0].confidenceLevel>=75?'var(--r0)':activeHashResult.threatfox.iocs[0].confidenceLevel>=50?'var(--r1)':'var(--r2)'}">
                          {{ activeHashResult.threatfox.iocs[0].confidenceLevel }}%
                        </span>
                      </div>
                      <div v-if="activeHashResult.threatfox.iocs[0].firstSeen" class="kv">
                        <span class="kv-key">First Seen</span><span class="kv-val">{{ activeHashResult.threatfox.iocs[0].firstSeen }}</span>
                      </div>
                      <div v-if="activeHashResult.threatfox.iocs[0].tags?.length" class="px-3 pb-3 pt-1 flex flex-wrap gap-1">
                        <span v-for="tag in activeHashResult.threatfox.iocs[0].tags" :key="tag" class="hash-tag">{{ tag }}</span>
                      </div>
                    </template>
                    <div v-if="activeHashResult.threatfox.queryStatus!=='ok'" class="kv">
                      <span class="kv-val text-t3 italic" style="font-size:0.66rem">
                        {{ isThreatFoxMissStatus(activeHashResult.threatfox.queryStatus) ? 'No ThreatFox intelligence for this hash.' : activeHashResult.threatfox.queryStatus }}
                      </span>
                    </div>
                  </div>
                </div>

              </div><!-- /sub-grid -->

              <!-- JSON panel -->
              <div class="px-4 pb-4">
                <div class="json-panel">
                  <button class="hash-source-link float-right mb-2" @click="copyHashJSON">COPY</button>
                  <pre><code v-html="highlightedHashJSON"></code></pre>
                </div>
              </div>

            </div><!-- /hash-card -->
          </div>

          <div v-else-if="allHashResults[activeHashIdx]?.error" class="vcard animate-fade-up">
            <div class="vcard-head"><span class="vcard-title">Error</span></div>
            <div class="kv"><span class="kv-val" style="color:var(--r0)">{{ allHashResults[activeHashIdx].error }}</span></div>
          </div>
        </div>

        <!-- ── HASH TABLE ── -->
        <div v-show="hashView==='table'">
          <results-table
            :visible-cols="visibleHashTableCols" :sorted-rows="sortedHashRows"
            :sort-col="hashSortCol" :sort-asc="hashSortAsc"
            :render-cell="renderHashTableCell"
            @sort="sortHashTable"
            @row-click="row => { activeHashIdx = row._idx; setHashView('cards'); }">
          </results-table>
        </div>
      </div>

    </div><!-- /hash section -->
    <!-- ══════════════════════════════════════════════════════════════════
         DOMAIN SCAN
    ══════════════════════════════════════════════════════════════════════ -->
    <div v-show="currentIOCMode==='domain'">

      <!-- Scan panel -->
      <div class="border border-white/10 bg-ink1 p-3.5 rounded-md mb-5 transition-all">
        <div class="flex gap-2.5">
          <textarea v-model="domainInputText" rows="2"
            class="flex-1 bg-ink2 border border-white/12 text-t1 font-mono text-sm px-3.5 py-2.5 rounded-sm resize-none outline-none transition-all focus:border-prime/40 leading-relaxed"
            placeholder="evil.com, malware-c2.ru — one per line"
            @keydown.enter.exact.prevent="doDomainScan"></textarea>
          <div class="flex flex-col gap-2 flex-shrink-0 items-stretch">
            <button class="bg-prime text-ink font-display font-bold tracking-widest text-sm px-6 rounded-sm flex-1 transition-all hover:bg-blue-400 shadow-prime hover:shadow-prime-lg"
                    :disabled="isDomainLoading" @click="doDomainScan">SCAN</button>
            <span v-if="isDomainLoading" class="loader self-center"></span>
          </div>
        </div>
        <div class="flex items-center gap-2.5 mt-2.5 flex-wrap">
          <div v-if="domainBulkCount" class="flex items-center gap-1.5 text-xs text-t2">
            <span class="font-mono font-bold" style="color:var(--c)">{{ domainBulkCount }}</span> domains
            <button class="px-2 py-0.5 rounded-pill border border-white/10 text-t3 text-xs hover:text-t1 transition-all" @click="clearDomainBulk">✕</button>
          </div>
          <label class="flex items-center gap-1.5 px-2.5 py-1 rounded-pill border border-white/10 text-t3 text-xs font-medium cursor-pointer hover:text-t1 transition-all">
            ↑ Load File <input type="file" class="hidden" accept=".txt,.csv" @change="handleDomainFileUpload">
          </label>
          <div class="flex items-center gap-2 cursor-pointer ml-auto" @click="domainUseCache=!domainUseCache">
            <button class="tog" :class="{on: domainUseCache}"></button>
            <span class="text-xs text-t3 select-none">Cache</span>
          </div>
        </div>
      </div>

      <div v-if="domainError" class="flex items-center gap-2 px-4 py-2.5 rounded-sm mb-4 text-sm animate-fade-up"
           style="color:var(--r0);background:var(--r0a);border:1px solid rgba(252,129,129,0.25);border-left:2px solid var(--r0)">⚠ {{ domainError }}</div>

      <div v-if="allDomainResults.length">
        <!-- Toolbar -->
        <div class="flex items-center gap-2 mb-4 flex-wrap animate-fade-up">
          <div class="flex bg-ink2 border border-white/10 rounded-pill p-0.5 gap-0.5">
            <button class="px-4 py-1.5 text-xs font-semibold tracking-widest uppercase rounded-pill transition-all"
                    :class="domainView==='cards' ? 'bg-ink4 text-t1' : 'text-t3 hover:text-t2'"
                    @click="setDomainView('cards')">Cards</button>
            <button class="px-4 py-1.5 text-xs font-semibold tracking-widest uppercase rounded-pill transition-all"
                    :class="domainView==='table' ? 'bg-ink4 text-t1' : 'text-t3 hover:text-t2'"
                    @click="setDomainView('table')">Table</button>
          </div>
          <div class="flex items-center gap-1.5 ml-auto">
            <button class="flex items-center gap-1 px-3 py-1.5 border border-white/12 text-t2 text-xs font-medium tracking-wide rounded-pill transition-all hover:border-prime/40 hover:text-prime hover:bg-prime-dim" @click="exportDomainCSV">↓ CSV</button>
            <button class="flex items-center gap-1 px-3 py-1.5 border border-white/12 text-t2 text-xs font-medium tracking-wide rounded-pill transition-all hover:border-prime/40 hover:text-prime hover:bg-prime-dim" @click="exportDomainJSON">↓ JSON</button>
          </div>
        </div>

        <!-- Domain chip tabs -->
        <div v-if="allDomainResults.length > 1 && domainView==='cards'" class="flex flex-wrap gap-1.5 mb-5">
          <div v-for="(e,i) in allDomainResults" :key="i"
               class="ip-tab" :class="{active: i===activeDomainIdx}" @click="activeDomainIdx=i">
            <span class="ip-tab-dot" :style="{background: riskDotColor((e.result||e).riskLevel)}"></span>
            {{ (e.result||e).domain || e.ioc || '?' }}
          </div>
        </div>

        <!-- Cards -->
        <div v-show="domainView==='cards'">
          <div v-if="activeDomainResult">
            <div class="flex items-center gap-3 mb-5 flex-wrap animate-fade-up">
              <span :class="['risk-pill','risk-'+(activeDomainResult.riskLevel||'CLEAN')]">{{ activeDomainResult.riskLevel || 'CLEAN' }}</span>
              <span class="font-mono text-base text-t1">{{ activeDomainResult.domain }}</span>
            </div>
            <div v-if="hasCacheHits(activeDomainResult)" class="flex items-center gap-2 mb-5 flex-wrap animate-fade-up">
              <span class="text-[11px] uppercase tracking-[0.16em] text-t3">Cache Hit</span>
              <span v-for="label in cacheHitLabels(activeDomainResult)" :key="'domain-cache-'+label"
                    class="text-xs px-2 py-0.5 border rounded-pill text-prime border-prime/20 bg-prime/10">
                {{ label }}
              </span>
              <span v-if="activeDomainResult.cached" class="text-xs px-2 py-0.5 border rounded-pill text-[#7ee0a0] border-[#7ee0a0]/20 bg-[#7ee0a0]/10">
                All Cached
              </span>
            </div>
            <details v-if="diagnosticEntries(activeDomainResult).length" class="diag-panel mb-5">
              <summary class="diag-summary">
                <span>Diagnostics</span>
                <span class="diag-summary-meta">{{ diagnosticEntries(activeDomainResult).length }} sources</span>
              </summary>
              <div class="diag-grid">
                <div v-for="entry in diagnosticEntries(activeDomainResult)" :key="'domain-diag-'+entry.key"
                     class="diag-row">
                  <div class="diag-source">
                    <span class="diag-source-name">{{ entry.label }}</span>
                    <span class="diag-source-key">{{ entry.key }}</span>
                  </div>
                  <div class="diag-badges">
                    <span :class="diagnosticCacheClass(entry.cache)">{{ diagnosticCacheLabel(entry.cache) }}</span>
                    <span :class="diagnosticStatusClass(entry.status)">{{ diagnosticStatusLabel(entry.status) }}</span>
                    <span v-if="entry.error" class="diag-chip status-error max-w-[24rem] truncate" :title="entry.error">{{ entry.error }}</span>
                  </div>
                </div>
              </div>
            </details>
            <div class="grid gap-3 mb-4" style="grid-template-columns:repeat(auto-fill,minmax(280px,1fr))">

              <!-- VT Domain card -->
              <div v-if="activeDomainResult.vtDomain" class="vcard animate-fade-up">
                <div class="vcard-head">
                  <span class="vcard-title">🧪 VirusTotal</span>
                  <div class="flex items-center gap-2">
                    <span v-if="activeDomainResult.vtDomain.error" class="mb-notfound-badge">Error</span>
                    <a v-if="domainResultLinks && domainResultLinks.virustotal"
                       :href="domainResultLinks.virustotal" target="_blank" rel="noopener" class="vcard-link">↗ VirusTotal</a>
                  </div>
                </div>
                <div class="vcard-body">
                  <template v-if="!activeDomainResult.vtDomain.error">
                    <div class="kv-row">
                      <span class="kv-key">S / U / H</span>
                      <span class="kv-val">{{ (activeDomainResult.vtDomain.suspicious||0)+' / '+(activeDomainResult.vtDomain.undetected||0)+' / '+(activeDomainResult.vtDomain.harmless||0) }}</span>
                    </div>
                    <div class="vt-pills" style="padding:8px 0 4px">
                      <span class="vt-pill mal">Malicious · {{ activeDomainResult.vtDomain.malicious }}</span>
                      <span class="vt-pill sus">Suspicious · {{ activeDomainResult.vtDomain.suspicious||0 }}</span>
                      <span class="vt-pill ok">Harmless · {{ activeDomainResult.vtDomain.harmless||0 }}</span>
                      <span class="vt-pill unk">Undetected · {{ activeDomainResult.vtDomain.undetected||0 }}</span>
                    </div>
                    <div v-if="activeDomainResult.vtDomain.suggestedThreatLabel" class="kv-row">
                      <span class="kv-key">Threat</span>
                      <span class="kv-val" style="color:var(--r0)">{{ activeDomainResult.vtDomain.suggestedThreatLabel }}</span>
                    </div>
                    <div v-if="activeDomainResult.vtDomain.reputation != null" class="kv-row">
                      <span class="kv-key">Reputation</span>
                      <span class="kv-val font-bold" :style="{color: activeDomainResult.vtDomain.reputation<0?'var(--r0)':activeDomainResult.vtDomain.reputation>0?'var(--r4)':'var(--t3)'}">
                        {{ activeDomainResult.vtDomain.reputation>0?'+':'' }}{{ activeDomainResult.vtDomain.reputation }}
                      </span>
                    </div>
                    <div v-if="activeDomainResult.vtDomain.registrar" class="kv-row">
                      <span class="kv-key">Registrar</span><span class="kv-val">{{ activeDomainResult.vtDomain.registrar }}</span>
                    </div>
                    <div v-if="activeDomainResult.vtDomain.creationDate" class="kv-row">
                      <span class="kv-key">Created</span><span class="kv-val">{{ activeDomainResult.vtDomain.creationDate }}</span>
                    </div>
                    <div v-if="activeDomainResult.vtDomain.aRecords && activeDomainResult.vtDomain.aRecords.length" class="kv-row" style="align-items:flex-start">
                      <span class="kv-key" style="padding-top:2px">A Records</span>
                      <span class="kv-val" style="font-size:0.65rem">{{ activeDomainResult.vtDomain.aRecords.join(', ') }}</span>
                    </div>
                    <div v-if="activeDomainResult.vtDomain.categories && activeDomainResult.vtDomain.categories.length"
                         class="border-t border-white/6 pt-2 pb-1 mt-1">
                      <div class="text-xs font-bold tracking-widest uppercase mb-1.5" style="color:#565e6e;font-size:0.54rem">Categories</div>
                      <div class="flex flex-wrap gap-1">
                        <span v-for="cat in activeDomainResult.vtDomain.categories" :key="cat"
                              class="text-xs px-2 py-0.5 border rounded font-medium"
                              style="color:#818cf8;border-color:rgba(129,140,248,0.28);background:rgba(129,140,248,0.08);font-size:0.6rem">{{ cat }}</span>
                      </div>
                    </div>
                  </template>
                  <div v-else class="kv-row"><span class="kv-val text-t3 italic text-xs">{{ activeDomainResult.vtDomain.error }}</span></div>
                </div>
              </div>

              <!-- ThreatFox Domain card -->
              <div v-if="showThreatFoxCard(activeDomainResult.threatfox)" class="vcard animate-fade-up-2">
                <div class="vcard-head">
                  <span class="vcard-title">🦊 ThreatFox</span>
                  <div class="flex items-center gap-2">
                    <span v-if="hasThreatFoxHit(activeDomainResult.threatfox)" class="mb-found-badge">✓ Found</span>
                    <span v-else class="mb-notfound-badge">{{ activeDomainResult.threatfox.queryStatus || 'No result' }}</span>
                    <a :href="'https://threatfox.abuse.ch/browse.php?search=ioc%3A'+activeDomainResult.domain"
                       target="_blank" rel="noopener" class="vcard-link">↗ ThreatFox</a>
                  </div>
                </div>
                <div class="vcard-body">
                  <template v-if="activeDomainResult.threatfox.queryStatus==='ok'">
                    <div v-if="activeDomainResult.threatfox.malware" class="kv-row">
                      <span class="kv-key">Malware</span>
                      <span class="kv-val font-bold" style="color:var(--r0)">{{ activeDomainResult.threatfox.malware }}</span>
                    </div>
                    <div v-if="activeDomainResult.threatfox.threatType" class="kv-row">
                      <span class="kv-key">Threat Type</span><span class="kv-val">{{ activeDomainResult.threatfox.threatType }}</span>
                    </div>
                    <div v-if="activeDomainResult.threatfox.confidenceLevel != null" class="kv-row">
                      <span class="kv-key">Confidence</span>
                      <span class="kv-val font-bold" :style="{color: activeDomainResult.threatfox.confidenceLevel>=75?'var(--r0)':activeDomainResult.threatfox.confidenceLevel>=50?'var(--r1)':'var(--r2)'}">
                        {{ activeDomainResult.threatfox.confidenceLevel }}%
                      </span>
                    </div>
                    <div v-if="activeDomainResult.threatfox.firstSeen" class="kv-row">
                      <span class="kv-key">First Seen</span><span class="kv-val">{{ activeDomainResult.threatfox.firstSeen }}</span>
                    </div>
                    <div v-if="activeDomainResult.threatfox.reporter" class="kv-row">
                      <span class="kv-key">Reporter</span><span class="kv-val">{{ activeDomainResult.threatfox.reporter }}</span>
                    </div>
                    <div v-if="activeDomainResult.threatfox.tags && activeDomainResult.threatfox.tags.length"
                         class="flex flex-wrap gap-1 pt-2 mt-1 border-t border-white/6">
                      <span v-for="tag in activeDomainResult.threatfox.tags" :key="tag" class="hash-tag">{{ tag }}</span>
                    </div>
                  </template>
                  <div v-if="activeDomainResult.threatfox.queryStatus !== 'ok'" class="kv-row">
                    <span class="kv-val text-t3 italic text-xs">
                      {{ isThreatFoxMissStatus(activeDomainResult.threatfox.queryStatus) ? 'No ThreatFox intelligence for this domain.' : activeDomainResult.threatfox.queryStatus }}
                    </span>
                  </div>
                </div>
              </div>

            </div><!-- /cards grid -->

            <div class="json-panel animate-fade-up">
              <button class="float-right mb-2 px-2.5 py-0.5 border border-white/10 rounded text-t3 font-mono text-xs tracking-widest transition-all hover:border-prime/40 hover:text-prime"
                      @click="copyDomainJSON">COPY</button>
              <pre><code v-html="highlightedDomainJSON"></code></pre>
            </div>
          </div>

          <div v-else-if="activeDomainEntry && activeDomainEntry.error" class="vcard animate-fade-up">
            <div class="vcard-head"><span class="vcard-title">Error</span></div>
            <div class="vcard-body"><span class="kv-val" style="color:var(--r0)">{{ activeDomainEntry.error }}</span></div>
          </div>
        </div>

        <!-- Table view -->
        <div v-show="domainView==='table'" class="overflow-x-auto animate-fade-up">
          <results-table
            :visible-cols="visibleDomainTableCols" :sorted-rows="sortedDomainRows"
            :sort-col="domainSortCol" :sort-asc="domainSortAsc"
            :render-cell="renderDomainTableCell"
            @sort="sortDomainTable"
            @row-click="row => { activeDomainIdx=row._idx; setDomainView('cards'); }">
          </results-table>
        </div>
      </div>

    </div><!-- /domain -->

  </div><!-- /page body -->

  `
});
