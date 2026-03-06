// components/IOCScanner.js
// ─────────────────────────────────────────────────────────────────────────────
// Root application component. Imports all state from composables and
// child components. The template is the full application UI, faithfully
// preserving every element from the original index.html.
// ─────────────────────────────────────────────────────────────────────────────

import ColumnDrawer from './ColumnDrawer.js';
import ResultsTable from './ResultsTable.js';

import {
    // State
    keys, scanMode, ipInputText, hashInputText,
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
    hashResultLinks, signerDetailObj, signerIsRevoked, signerIsInvalid, vtNotFound,
    networkRows, highlightedJSON, highlightedHashJSON,
    visibleTableCols, sortedTableRows,
    visibleHashTableCols, sortedHashRows,
    // Methods
    switchIOCMode, setView, setHashView, switchTab, switchToCard,
    riskDotColor, vtStatPart, abuseColor, formatBytes, toArr, yn,
    openColDrawer, closeColDrawer, toggleHistDrawer,
    clearHistory, reScan,
    doIPScan, doHashScanAction,
    handleIPFileUpload, handleIPDrop, clearIPBulk,
    handleHashFileUpload, clearHashBulk,
    copyJSON, copyHashJSON,
    toggleCopyMenu, toggleHashCopyMenu,
    copyClipboard, copyHashClipboard,
    exportCSV, exportJSON, exportHashCSV, exportHashJSON,
    sortTable, renderTableCell, sortHashTable, renderHashTableCell,
} from '../composables/useIOCScan.js';

const { defineComponent } = Vue;

export default defineComponent({
    name: 'IOCScanner',
    components: { ColumnDrawer, ResultsTable },

    setup() {
        return {
            // State
            keys, scanMode, ipInputText, hashInputText,
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
            hashResultLinks, signerDetailObj, signerIsRevoked, signerIsInvalid, vtNotFound,
            networkRows, highlightedJSON, highlightedHashJSON,
            visibleTableCols, sortedTableRows,
            visibleHashTableCols, sortedHashRows,
            // Methods
            switchIOCMode, setView, setHashView, switchTab, switchToCard,
            riskDotColor, vtStatPart, abuseColor, formatBytes, toArr, yn,
            openColDrawer, closeColDrawer, toggleHistDrawer,
            clearHistory, reScan,
            doIPScan, doHashScanAction,
            handleIPFileUpload, handleIPDrop, clearIPBulk,
            handleHashFileUpload, clearHashBulk,
            copyJSON, copyHashJSON,
            toggleCopyMenu, toggleHashCopyMenu,
            copyClipboard, copyHashClipboard,
            exportCSV, exportJSON, exportHashCSV, exportHashJSON,
            sortTable, renderTableCell, sortHashTable, renderHashTableCell,
        };
    },

    template: `
  <div :class="['shell', wideShell ? 'wide' : '']" id="shell">

    <!-- ══ HEADER ══════════════════════════════════════════════════════ -->
    <header class="flex items-end justify-between flex-wrap gap-3 py-8 border-b mb-8" style="border-color:#1e2d42">
      <!-- Brand -->
      <div class="flex items-center gap-4">
        <div class="w-10 h-10 border flex items-center justify-center text-xl" style="border-color:#38bdf8;color:#38bdf8;background:rgba(56,189,248,0.06)">⚡</div>
        <div>
          <div class="font-bold text-2xl tracking-tight" style="font-family:'Syne',sans-serif">
            <span style="color:#e2e8f0">ioc</span><span style="color:#38bdf8">scan</span>
          </div>
          <div class="text-xs tracking-widest uppercase" style="color:#4d6480;font-size:0.58rem">Threat Intelligence · IP &amp; Hash Enrichment</div>
        </div>
      </div>

      <!-- Right side controls -->
      <div class="flex items-center gap-3 flex-wrap">
        <!-- Source badges -->
        <div class="flex gap-2">
          <span class="text-xs px-2 py-1 border tracking-widest uppercase" style="font-size:0.56rem;border-color:rgba(56,189,248,0.4);color:#38bdf8">VirusTotal</span>
          <span class="text-xs px-2 py-1 border tracking-widest uppercase" style="font-size:0.56rem;border-color:rgba(251,146,60,0.4);color:#fb923c">AbuseIPDB</span>
          <span class="text-xs px-2 py-1 border tracking-widest uppercase" style="font-size:0.56rem;border-color:rgba(52,211,153,0.4);color:#34d399">IPAPI.IS</span>
          <span class="text-xs px-2 py-1 border tracking-widest uppercase" style="font-size:0.56rem;border-color:rgba(192,132,252,0.4);color:#c084fc">abuse.ch</span>
          <span class="text-xs px-2 py-1 border tracking-widest uppercase" style="font-size:0.56rem;border-color:rgba(251,191,36,0.4);color:#fbbf24">ThreatFox</span>
        </div>

        <!-- History drawer -->
        <div style="position:relative">
          <button class="action-btn flex items-center gap-2" @click="toggleHistDrawer">
            ⏱ HISTORY <span class="text-xs px-1 border" style="border-color:#243550;color:#38bdf8">{{ scanHist.length }}</span>
          </button>
          <div class="hist-drawer" :class="{open: histDrawerOpen}">
            <div class="flex items-center justify-between px-4 py-3 border-b" style="border-color:#1e2d42">
              <span class="text-xs font-bold tracking-widest uppercase" style="color:#94a3b8">History</span>
              <div class="flex gap-2">
                <button class="action-btn text-xs" @click="clearHistory">Clear All</button>
                <button class="action-btn" @click="toggleHistDrawer">✕</button>
              </div>
            </div>
            <div class="overflow-y-auto flex-1">
              <p v-if="!scanHist.length" class="text-center py-6 text-xs" style="color:#2e4060">No scans yet.</p>
              <div v-for="(h, i) in scanHist" :key="h.ip + i" class="hist-item" @click="reScan(h.ip)">
                <div class="flex items-center gap-2">
                  <span class="text-xs" style="color:#2e4060">{{ i+1 }}</span>
                  <span style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:#cbd5e1">{{ h.ip }}</span>
                  <span v-if="h.scanCount > 1" style="font-size:0.5rem;color:#2e4060;border:1px solid #2e4060;padding:1px 5px;">×{{ h.scanCount }}</span>
                  <span style="font-size:0.6rem;color:#4d6480">{{ h.scanCount > 1 ? h.lastSeen : h.time }}</span>
                </div>
                <span :class="['risk-pill', 'risk-' + h.risk]" style="font-size:0.55rem;padding:2px 7px">{{ h.risk }}</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Column drawer component -->
        <column-drawer></column-drawer>
      </div>
    </header>

    <!-- ══ API KEYS ══════════════════════════════════════════════════════ -->
    <div class="border p-5 mb-6 relative" style="border-color:#1e2d42;background:#0d1320">
      <span class="absolute -top-2 left-3 px-2 text-xs font-bold tracking-widest uppercase" style="background:#0d1320;color:#4d6480;font-size:0.58rem">API Keys</span>
      <div class="grid gap-4" style="grid-template-columns:repeat(auto-fit,minmax(220px,1fr))">
        <div>
          <label class="block text-xs font-bold tracking-widest uppercase mb-2" style="color:#4d6480;font-size:0.58rem">VirusTotal</label>
          <input type="password" v-model="keys.vt" class="key-input" placeholder="Required for complex mode…">
        </div>
        <div>
          <label class="block text-xs font-bold tracking-widest uppercase mb-2" style="color:#4d6480;font-size:0.58rem">AbuseIPDB</label>
          <input type="password" v-model="keys.abuse" class="key-input" placeholder="Required for complex mode…">
        </div>
        <div>
          <label class="block text-xs font-bold tracking-widest uppercase mb-2" style="color:#4d6480;font-size:0.58rem">IPAPI.IS <span style="color:#2e4060">(optional)</span></label>
          <input type="password" v-model="keys.ipapi" class="key-input" placeholder="Leave blank for free tier…">
        </div>
        <div>
          <label class="block text-xs font-bold tracking-widest uppercase mb-2" style="color:#4d6480;font-size:0.58rem">abuse.ch <span style="color:#2e4060">(optional)</span></label>
          <input type="password" v-model="keys.abusech" class="key-input" placeholder="Used for MalwareBazaar + ThreatFox…">
        </div>
      </div>
    </div>

    <!-- ══ MODE TABS ════════════════════════════════════════════════════ -->
    <div class="flex border-b mb-6" style="border-color:#1e2d42">
      <button class="ioc-tab" :class="{active: currentIOCMode==='ip'}"   @click="switchIOCMode('ip')">● IP Address</button>
      <button class="ioc-tab" :class="{active: currentIOCMode==='hash'}" @click="switchIOCMode('hash')">● File Hash</button>
    </div>

    <!-- ══ IP SCAN SECTION ══════════════════════════════════════════════ -->
    <div v-show="currentIOCMode==='ip'">
      <div class="border p-4 mb-6" style="border-color:#1e2d42;background:#0d1320;border-top:2px solid #0ea5e9">
        <div class="flex gap-3" style="align-items:stretch">
          <div class="flex-1 min-w-0 relative" :class="{'drag-over': isDragging}" @dragover.prevent="isDragging=true" @dragleave="isDragging=false" @drop.prevent="handleIPDrop">
            <textarea id="ipInput" v-model="ipInputText" class="scan-input" rows="2"
              placeholder="8.8.8.8, 1.1.1.1 — or drag &amp; drop a .txt / .csv file"
              style="width:100%" @keydown.enter.exact.prevent="doIPScan"></textarea>
          </div>
          <div class="flex flex-col gap-2" style="flex-shrink:0">
            <select v-model="scanMode" class="key-input" style="cursor:pointer;height:44px">
              <option value="complex">Complex (all sources)</option>
              <option value="simple">Simple (ipapi.is only)</option>
            </select>
            <div class="flex gap-2 items-center">
              <button class="scan-btn" :disabled="isIPLoading" @click="doIPScan" style="flex:1">SCAN</button>
              <span v-if="isIPLoading" class="loader"></span>
            </div>
          </div>
        </div>
        <!-- Bulk preview -->
        <div v-if="ipBulkCount" class="bulk-preview mt-2">
          <span style="color:#38bdf8">📋</span>
          <span><span style="color:#cbd5e1;font-weight:600">{{ ipBulkCount }}</span> IPs detected</span>
          <button class="action-btn" @click="clearIPBulk">✕ Clear</button>
        </div>
        <!-- File upload row -->
        <div class="flex items-center gap-3 mt-3 pt-3 border-t" style="border-color:#1e2d42">
          <label class="action-btn cursor-pointer">
            📁 Load File <input type="file" class="hidden" accept=".txt,.csv,.log" @change="handleIPFileUpload">
          </label>
          <div class="flex items-center gap-2" style="cursor:pointer" @click="ipUseCache=!ipUseCache">
            <button class="tog" :class="{on: ipUseCache}" style="cursor:pointer"></button>
            <span style="font-size:0.68rem;color:#4d6480;user-select:none">Use Cache</span>
          </div>
        </div>
      </div>

      <!-- Error -->
      <div v-if="ipError" class="err-box mb-4">❌ {{ ipError }}</div>

      <!-- IP Results -->
      <div v-if="allResults.length">
        <!-- View toggle + export bar -->
        <div class="flex items-center justify-between flex-wrap gap-3 mb-4">
          <div class="flex gap-0">
            <button class="view-btn" :class="{active: currentView==='cards'}" @click="setView('cards')">Cards</button>
            <button class="view-btn" :class="{active: currentView==='table'}" @click="setView('table')">Table</button>
          </div>
          <div class="flex items-center gap-2">
            <span class="text-xs" style="color:#4d6480;font-size:0.62rem" v-if="currentView==='table'">
              Showing <span style="color:#cbd5e1">{{ allResults.filter(e=>e.result).length }}</span> IPs
            </span>
            <div class="copy-split">
              <button class="export-btn copy-main" @click="toggleCopyMenu">⎘ Copy</button>
              <button class="export-btn copy-arrow" @click="toggleCopyMenu">▾</button>
              <div class="copy-menu" :class="{open: copyMenuOpen}" @mouseleave="copyMenuOpen=false">
                <div class="copy-menu-item" @click="copyClipboard('json')">Copy as JSON</div>
                <div class="copy-menu-item" @click="copyClipboard('csv')">Copy as CSV</div>
                <div class="copy-menu-item" @click="copyClipboard('ips')">Copy IPs only</div>
              </div>
            </div>
            <button class="export-btn" @click="exportCSV">↓ CSV</button>
            <button class="export-btn" @click="exportJSON">↓ JSON</button>
          </div>
        </div>

        <!-- IP chip tabs (multi-IP, cards view only) -->
        <div v-if="allResults.length > 1 && currentView==='cards'" class="flex flex-wrap gap-1 mb-4">
          <div v-for="(r, i) in allResults" :key="r.ip" class="ip-tab" :class="{active: i===activeIdx}" @click="switchTab(i)">
            <span class="ip-tab-dot" :style="{background: riskDotColor(r.result ? r.result.riskLevel : null)}"></span>
            {{ r.ip }}
          </div>
        </div>

        <!-- Cards view -->
        <div v-show="currentView==='cards'" id="cardsView">
          <div v-if="activeResult">
            <!-- Risk pill -->
            <div v-if="colVisible.risk" class="mb-4">
              <span :class="['risk-pill', 'risk-' + (activeResult.riskLevel||'CLEAN')]">{{ activeResult.riskLevel || 'CLEAN' }}</span>
              <span style="font-family:'JetBrains Mono',monospace;font-size:0.8rem;color:#e2e8f0;margin-left:12px">{{ activeResultIP }}</span>
            </div>
            <div class="cards">
              <!-- Network card -->
              <div v-if="colVisible.network && networkRows.length" class="card" id="card-network">
                <div class="card-head">
                  <span class="card-head-left">🌍 Network Info</span>
                  <a :href="'https://api.ipapi.is/?q='+activeResultIP" target="_blank" rel="noopener" class="card-source-link">↗ ipapi.is</a>
                </div>
                <div v-for="[k,v,fkey] in networkRows" :key="k" class="kv" :data-field="fkey" v-show="!fkey || fieldVisible[fkey]">
                  <span class="kv-key">{{ k }}</span><span class="kv-val" v-html="v"></span>
                </div>
              </div>
              <!-- AbuseIPDB card -->
              <div v-if="colVisible.abuse && activeResult.abuseipdb.confidenceScore != null" class="card" id="card-abuse">
                <div class="card-head">
                  <span class="card-head-left">🚨 AbuseIPDB</span>
                  <a :href="'https://www.abuseipdb.com/check/'+activeResultIP" target="_blank" rel="noopener" class="card-source-link">↗ AbuseIPDB</a>
                </div>
                <div class="kv" v-show="fieldVisible['ab-score']">
                  <span class="kv-key">Confidence</span>
                  <span class="kv-val" :style="{color: abuseColor(activeResult.abuseipdb.confidenceScore), fontWeight:600}">{{ activeResult.abuseipdb.confidenceScore }}%</span>
                </div>
                <div class="meter" v-show="fieldVisible['ab-meter']">
                  <div class="meter-bar" :style="{width: activeResult.abuseipdb.confidenceScore+'%', background: abuseColor(activeResult.abuseipdb.confidenceScore)}"></div>
                </div>
                <div class="kv" v-show="fieldVisible['ab-reports']">
                  <span class="kv-key">Total Reports</span><span class="kv-val">{{ activeResult.abuseipdb.totalReports ?? '—' }}</span>
                </div>
                <div class="kv" v-show="fieldVisible['ab-lastreport']">
                  <span class="kv-key">Last Reported</span><span class="kv-val">{{ activeResult.abuseipdb.lastReportedAt || '—' }}</span>
                </div>
              </div>
              <!-- VirusTotal card -->
              <div v-if="colVisible.vt && activeResult.virustotal.malicious != null" class="card" id="card-vt">
                <div class="card-head">
                  <span class="card-head-left">🧪 VirusTotal</span>
                  <a :href="'https://www.virustotal.com/gui/ip-address/'+activeResultIP" target="_blank" rel="noopener" class="card-source-link">↗ VirusTotal</a>
                </div>
                <div class="kv" v-show="fieldVisible['vt-summary']">
                  <span class="kv-key">Summary (S/U/H)</span><span class="kv-val">{{ activeResult.virustotal ? (activeResult.virustotal.suspicious ?? 0) + '/' + (activeResult.virustotal.undetected ?? 0) + '/' + (activeResult.virustotal.harmless ?? 0) : '—' }}</span>
                </div>
                <div class="vt-pills">
                  <span v-show="fieldVisible['vt-malicious']"  class="vt-pill mal">🔴 Malicious: {{ activeResult.virustotal.malicious }}</span>
                  <span v-show="fieldVisible['vt-suspicious']" class="vt-pill sus">🟡 Suspicious: {{ activeResult.virustotal.suspicious ?? 0 }}</span>
                  <span v-show="fieldVisible['vt-harmless']"   class="vt-pill ok">🟢 Harmless: {{ vtStatPart(2) }}</span>
                  <span v-show="fieldVisible['vt-undetected']" class="vt-pill unk">⬜ Undetected: {{ vtStatPart(1) }}</span>
                </div>
              </div>
              <!-- ThreatFox card (IP mode) -->
              <div v-if="activeResult.threatfox" class="card" id="card-tf">
                <div class="card-head">
                  <span class="card-head-left">🦊 ThreatFox</span>
                  <div class="flex items-center gap-2">
                    <span v-if="activeResult.threatfox.queryStatus === 'ok'" class="mb-found-badge">✓ Found</span>
                    <span v-else class="mb-notfound-badge">✗ {{ activeResult.threatfox.queryStatus || 'No Result' }}</span>
                    <a :href="'https://threatfox.abuse.ch/browse.php?search=ioc%3A'+activeResultIP" target="_blank" rel="noopener" class="card-source-link">↗ ThreatFox</a>
                  </div>
                </div>
                <template v-if="activeResult.threatfox.queryStatus === 'ok'">
                  <div v-if="activeResult.threatfox.malware" class="kv">
                    <span class="kv-key">Malware</span>
                    <span class="kv-val" style="color:var(--red);font-weight:600">{{ activeResult.threatfox.malware }}</span>
                  </div>
                  <div v-if="activeResult.threatfox.threatType" class="kv">
                    <span class="kv-key">Threat Type</span><span class="kv-val">{{ activeResult.threatfox.threatType }}</span>
                  </div>
                  <div v-if="activeResult.threatfox.malwareAlias" class="kv">
                    <span class="kv-key">Aliases</span>
                    <span class="kv-val" style="color:var(--text1);font-size:0.68rem">{{ activeResult.threatfox.malwareAlias }}</span>
                  </div>
                  <div v-if="activeResult.threatfox.confidenceLevel != null" class="kv">
                    <span class="kv-key">Confidence</span>
                    <span class="kv-val" :style="{color: activeResult.threatfox.confidenceLevel >= 75 ? 'var(--red)' : activeResult.threatfox.confidenceLevel >= 50 ? 'var(--orange)' : 'var(--yellow)', fontWeight:600}">
                      {{ activeResult.threatfox.confidenceLevel }}%
                    </span>
                  </div>
                  <div v-if="activeResult.threatfox.firstSeen" class="kv">
                    <span class="kv-key">First Seen</span><span class="kv-val">{{ activeResult.threatfox.firstSeen }}</span>
                  </div>
                  <div v-if="activeResult.threatfox.lastSeen" class="kv">
                    <span class="kv-key">Last Seen</span><span class="kv-val">{{ activeResult.threatfox.lastSeen }}</span>
                  </div>
                  <div v-if="activeResult.threatfox.reporter" class="kv">
                    <span class="kv-key">Reporter</span>
                    <span class="kv-val" style="color:var(--text1)">{{ activeResult.threatfox.reporter }}</span>
                  </div>
                  <div v-if="activeResult.threatfox.tags && activeResult.threatfox.tags.length" class="hash-tags mt-2">
                    <span v-for="tag in activeResult.threatfox.tags" :key="tag" class="hash-tag">{{ tag }}</span>
                  </div>
                  <div v-if="activeResult.threatfox.malwareSamples && activeResult.threatfox.malwareSamples.length" class="mt-3">
                    <div class="vt-subsection-label">Associated Samples</div>
                    <div v-for="s in activeResult.threatfox.malwareSamples" :key="s.sha256_hash" class="kv mt-1" style="align-items:flex-start">
                      <span class="kv-key" style="font-size:0.58rem;padding-top:2px">SHA256</span>
                      <span class="kv-val" style="font-size:0.58rem;word-break:break-all">
                        <a v-if="s.malware_bazaar" :href="s.malware_bazaar" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:none">{{ s.sha256_hash }}</a>
                        <span v-else>{{ s.sha256_hash }}</span>
                      </span>
                    </div>
                  </div>
                </template>
                <div v-if="activeResult.threatfox.queryStatus !== 'ok'" class="kv mt-2">
                  <span class="kv-val" style="color:var(--muted);font-style:italic;font-size:0.68rem">
                    {{ activeResult.threatfox.queryStatus === 'no_results' ? 'No ThreatFox intelligence for this IP.' : activeResult.threatfox.queryStatus }}
                  </span>
                </div>
              </div>
            </div>
            <!-- JSON panel -->
            <div v-if="colVisible.json" class="json-panel mt-4" id="json-panel-wrap">
              <button class="copy-btn" @click="copyJSON">COPY JSON</button>
              <pre><code v-html="highlightedJSON"></code></pre>
            </div>
          </div>
          <div v-else-if="activeResultEntry && activeResultEntry.error" class="card">
            <div class="card-head">Error</div>
            <div style="color:var(--red)">{{ activeResultEntry.error }}</div>
          </div>
        </div>

        <!-- Table view -->
        <div v-show="currentView==='table'" id="tableView">
          <results-table
            :visible-cols="visibleTableCols"
            :sorted-rows="sortedTableRows"
            :sort-col="tableSortCol"
            :sort-asc="tableSortAsc"
            :render-cell="renderTableCell"
            @sort="sortTable"
            @row-click="row => switchToCard(row._idx)"
          ></results-table>
        </div>
      </div>
    </div>

    <!-- ══ HASH SCAN SECTION ════════════════════════════════════════════ -->
    <div v-show="currentIOCMode==='hash'">
      <div class="border p-4 mb-6" style="border-color:#1e2d42;background:#0d1320;border-top:2px solid #c084fc">
        <div class="flex gap-3" style="align-items:stretch">
          <textarea id="hashInput" v-model="hashInputText" class="scan-input" rows="3"
            placeholder="Paste MD5, SHA1, or SHA256 hashes — one per line"
            style="flex:1;min-width:0" @keydown.enter.exact.prevent="doHashScanAction"></textarea>
          <div class="flex flex-col gap-2" style="flex-shrink:0">
            <div class="flex gap-2 items-center">
              <button class="scan-btn" :disabled="isHashLoading" @click="doHashScanAction" style="flex:1">SCAN</button>
              <span v-if="isHashLoading" class="loader"></span>
            </div>
          </div>
        </div>
        <!-- Bulk preview -->
        <div v-if="hashBulkCount" class="bulk-preview mt-2">
          <span style="color:#c084fc">📋</span>
          <span><span style="color:#cbd5e1;font-weight:600">{{ hashBulkCount }}</span> hashes detected</span>
          <button class="action-btn" @click="clearHashBulk">✕ Clear</button>
        </div>
        <div class="flex items-center gap-3 mt-3 pt-3 border-t" style="border-color:#1e2d42">
          <label class="action-btn cursor-pointer">
            📁 Load File <input type="file" class="hidden" accept=".txt,.csv,.log" @change="handleHashFileUpload">
          </label>
          <div class="flex items-center gap-2" style="cursor:pointer" @click="hashUseCache=!hashUseCache">
            <button class="tog" :class="{on: hashUseCache}" style="cursor:pointer"></button>
            <span style="font-size:0.68rem;color:#4d6480;user-select:none">Use Cache</span>
          </div>
        </div>
      </div>

      <!-- Error -->
      <div v-if="hashError" class="err-box mb-4">❌ {{ hashError }}</div>

      <!-- Hash Results -->
      <div v-if="allHashResults.length">
        <!-- View toggle + export bar -->
        <div class="flex items-center justify-between flex-wrap gap-3 mb-4">
          <div class="flex gap-0">
            <button class="view-btn" :class="{active: hashView==='cards'}" @click="setHashView('cards')">Cards</button>
            <button class="view-btn" :class="{active: hashView==='table'}" @click="setHashView('table')">Table</button>
          </div>
          <div class="flex items-center gap-2">
            <div class="copy-split" style="position:relative">
              <button class="export-btn copy-main" id="hashClipboardBtn" @click="copyHashClipboard('json')">⎘ Copy</button>
              <button class="export-btn copy-arrow" @click="toggleHashCopyMenu">▾</button>
              <div class="copy-menu" :class="{open: hashCopyMenuOpen}" @mouseleave="hashCopyMenuOpen=false">
                <div class="copy-menu-item" @click="copyHashClipboard('json')">Copy as JSON</div>
                <div class="copy-menu-item" @click="copyHashClipboard('csv')">Copy as CSV</div>
                <div class="copy-menu-item" @click="copyHashClipboard('hashes')">Copy Hashes only</div>
              </div>
            </div>
            <button class="export-btn" @click="exportHashCSV">↓ CSV</button>
            <button class="export-btn" @click="exportHashJSON">↓ JSON</button>
          </div>
        </div>

        <!-- Hash chip tabs (multi-hash, cards view only) -->
        <div v-if="allHashResults.length > 1 && hashView==='cards'" class="flex flex-wrap gap-1 mb-4">
          <div v-for="(e, i) in allHashResults" :key="i" class="ip-tab" :class="{active: i===activeHashIdx}" @click="activeHashIdx=i">
            <span class="ip-tab-dot" :style="{background: riskDotColor((e.result||e).riskLevel)}"></span>
            {{ ((e.result||e).virustotal?.sha256||(e.result||e).virustotal?.sha1||(e.result||e).virustotal?.md5||e.hash||'?').slice(0,12) }}…
          </div>
        </div>

        <!-- Hash Cards view -->
        <div v-show="hashView==='cards'">
          <div v-if="activeHashResult" class="hash-result-card" :class="(activeHashResult.riskLevel||'').toLowerCase()">

            <!-- Card header: hash value + badges + source links -->
            <div class="hash-card-header">
              <div style="flex:1;min-width:0">
                <div class="hash-card-title">{{ (activeHashResult.virustotal && (activeHashResult.virustotal.sha256 || activeHashResult.virustotal.sha1 || activeHashResult.virustotal.md5)) || allHashResults[activeHashIdx]?.hash || '—' }}</div>
                <div class="hash-card-meta">
                  <span v-if="activeHashResult.riskLevel" :class="['risk-pill','risk-'+(activeHashResult.riskLevel)]">{{ activeHashResult.riskLevel }}</span>
                  <span v-if="activeHashResult.hashType"  class="hash-type-badge">{{ activeHashResult.hashType }}</span>
                  <span v-if="activeHashResult.virustotal && activeHashResult.virustotal.suggestedThreatLabel" class="hash-threat-label">{{ activeHashResult.virustotal.suggestedThreatLabel }}</span>
                </div>
              </div>
              <div class="flex gap-2" style="flex-shrink:0">
                <a v-if="hashResultLinks.virustotal && !vtNotFound" :href="hashResultLinks.virustotal" target="_blank" rel="noopener" class="hash-source-link">↗ VT</a>
                <span v-else-if="vtNotFound" class="hash-source-link-na" title="Hash not found in VirusTotal">✗ VT</span>
                <a v-if="hashResultLinks.malwarebazaar && activeHashResult.malwarebazaar && activeHashResult.malwarebazaar.queryStatus === 'ok'" :href="hashResultLinks.malwarebazaar" target="_blank" rel="noopener" class="hash-source-link">↗ MB</a>
                <span v-else-if="activeHashResult.malwarebazaar && activeHashResult.malwarebazaar.queryStatus && activeHashResult.malwarebazaar.queryStatus !== 'ok'" class="hash-source-link-na" title="Hash not found in MalwareBazaar">✗ MB</span>
              </div>
            </div>

            <!-- Hash Values row (full-width, above cards) -->
            <div class="border-b mb-4 pb-4" style="border-color:#1e2d42">
              <div class="hash-section-title" style="margin-bottom:8px">⬡ Hash Values</div>
              <div v-if="activeHashResult.virustotal && activeHashResult.virustotal.md5"    class="kv"><span class="kv-key">MD5</span><span class="kv-val">{{ activeHashResult.virustotal.md5 }}</span></div>
              <div v-if="activeHashResult.virustotal && activeHashResult.virustotal.sha1"   class="kv"><span class="kv-key">SHA1</span><span class="kv-val">{{ activeHashResult.virustotal.sha1 }}</span></div>
              <div v-if="activeHashResult.virustotal && activeHashResult.virustotal.sha256" class="kv"><span class="kv-key">SHA256</span><span class="kv-val">{{ activeHashResult.virustotal.sha256 }}</span></div>
            </div>

            <!-- Three-column card grid -->
            <div class="cards" style="margin-bottom:0">

              <!-- FILE INFO card -->
              <div class="card">
                <div class="card-head"><span class="card-head-left">📄 File Info</span></div>
                <div v-if="activeHashResult.virustotal && activeHashResult.virustotal.meaningfulName" class="kv">
                  <span class="kv-key">Name</span><span class="kv-val">{{ activeHashResult.virustotal.meaningfulName }}</span>
                </div>
                <div v-if="activeHashResult.virustotal && activeHashResult.virustotal.magic" class="kv">
                  <span class="kv-key">Magic</span><span class="kv-val">{{ activeHashResult.virustotal.magic }}</span>
                </div>
                <div v-if="activeHashResult.virustotal && activeHashResult.virustotal.magika" class="kv">
                  <span class="kv-key">Magika</span><span class="kv-val">{{ activeHashResult.virustotal.magika }}</span>
                </div>
                <div v-if="activeHashResult.virustotal && activeHashResult.virustotal.fileSize" class="kv">
                  <span class="kv-key">Size</span><span class="kv-val">{{ formatBytes(activeHashResult.virustotal.fileSize) }}</span>
                </div>
                <div v-if="activeHashResult.virustotal && toArr(activeHashResult.virustotal.signatureSigners).length" class="kv">
                  <span class="kv-key">Signer</span>
                  <span class="kv-val">{{ toArr(activeHashResult.virustotal.signatureSigners).join(', ') }}</span>
                </div>
                <!-- Code signing detail box -->
                <div v-if="activeHashResult.virustotal && toArr(activeHashResult.virustotal.signatureSigners).length" class="codesign-box">
                  <div class="flex items-center gap-2 mb-1">
                    <span style="font-size:0.62rem;color:#f87171;font-weight:700">⚠ Code Signed</span>
                    <span v-if="signerIsRevoked" class="revoked-badge">REVOKED</span>
                    <span v-else-if="signerIsInvalid" class="invalid-badge">INVALID</span>
                  </div>
                  <template v-if="signerDetailObj">
                    <div class="codesign-row"><span class="codesign-lbl">Issuer</span><span class="codesign-val">{{ signerDetailObj.certIssuer }}</span></div>
                    <div class="codesign-row"><span class="codesign-lbl">Entity</span><span class="codesign-val">{{ signerDetailObj.name }}</span></div>
                    <div class="codesign-row" v-if="signerDetailObj.validFrom"><span class="codesign-lbl">Valid</span><span class="codesign-val">{{ signerDetailObj.validFrom }} → {{ signerDetailObj.validTo }}</span></div>
                    <div class="codesign-status mt-1">{{ signerDetailObj.status }}</div>
                  </template>
                  <div v-else-if="activeHashResult.virustotal.signerDetail" class="codesign-revoked">{{ activeHashResult.virustotal.signerDetail }}</div>
                </div>
                <div v-if="!activeHashResult.virustotal || (!activeHashResult.virustotal.meaningfulName && !activeHashResult.virustotal.magic && !activeHashResult.virustotal.magika && !activeHashResult.virustotal.fileSize)" class="kv">
                  <span class="kv-key" style="font-style:italic;color:var(--dim)">No file info available</span>
                </div>
              </div>

              <!-- VIRUSTOTAL card -->
              <div v-if="(activeHashResult.virustotal && activeHashResult.virustotal.malicious != null) || vtNotFound" class="card">
                <div class="card-head">
                  <span class="card-head-left">🧪 VirusTotal</span>
                  <div class="flex items-center gap-2">
                    <span v-if="vtNotFound" class="mb-notfound-badge">✗ Not Found</span>
                    <a v-if="hashResultLinks.virustotal" :href="hashResultLinks.virustotal" target="_blank" rel="noopener" class="card-source-link">↗ VirusTotal</a>
                  </div>
                </div>
                <div v-if="vtNotFound" class="kv mt-2">
                  <span class="kv-val" style="color:var(--muted);font-style:italic;font-size:0.68rem">This hash was not found in VirusTotal.</span>
                </div>
                <template v-else-if="activeHashResult.virustotal">
                  <div class="vt-pills">
                    <span class="vt-pill mal">🔴 Malicious: {{ activeHashResult.virustotal.malicious }}</span>
                    <span class="vt-pill sus">🟡 Suspicious: {{ activeHashResult.virustotal.suspicious ?? 0 }}</span>
                    <span v-if="activeHashResult.virustotal.harmless   != null" class="vt-pill ok" >🟢 Harmless: {{ activeHashResult.virustotal.harmless }}</span>
                    <span v-if="activeHashResult.virustotal.undetected != null" class="vt-pill unk">⬜ Undetected: {{ activeHashResult.virustotal.undetected }}</span>
                  </div>
                  <div v-if="activeHashResult.virustotal.reputation != null" class="kv mt-3">
                    <span class="kv-key">Reputation</span>
                    <span class="kv-val" :style="{color: activeHashResult.virustotal.reputation < 0 ? 'var(--red)' : activeHashResult.virustotal.reputation > 0 ? 'var(--green)' : 'var(--muted)'}">
                      {{ activeHashResult.virustotal.reputation > 0 ? '+' : '' }}{{ activeHashResult.virustotal.reputation }}
                    </span>
                  </div>
                  <div v-if="toArr(activeHashResult.virustotal.popularThreatNames).length" class="mt-3">
                    <div class="vt-subsection-label">Threat Names</div>
                    <div class="flex flex-wrap gap-1 mt-1">
                      <span v-for="n in toArr(activeHashResult.virustotal.popularThreatNames)" :key="n" class="hash-family-badge">{{ n }}</span>
                    </div>
                  </div>
                  <div v-if="toArr(activeHashResult.virustotal.popularThreatCategories).length" class="mt-3">
                    <div class="vt-subsection-label">Threat Categories</div>
                    <div class="flex flex-wrap gap-1 mt-1">
                      <span v-for="c in toArr(activeHashResult.virustotal.popularThreatCategories)" :key="c" class="hash-category-badge">{{ c }}</span>
                    </div>
                  </div>
                  <div v-if="toArr(activeHashResult.virustotal.sandboxMalwareClassifications).length" class="mt-3">
                    <div class="vt-subsection-label">Sandbox Classifications</div>
                    <div class="flex flex-wrap gap-1 mt-1">
                      <span v-for="s in toArr(activeHashResult.virustotal.sandboxMalwareClassifications)" :key="s" class="sandbox-badge">{{ s }}</span>
                    </div>
                  </div>
                  <div v-if="activeHashResult.virustotal.sigmaAnalysisSummary && Object.keys(activeHashResult.virustotal.sigmaAnalysisSummary).length" class="mt-3">
                    <div class="vt-subsection-label">Sigma Rules</div>
                    <div v-for="(counts, ruleset) in activeHashResult.virustotal.sigmaAnalysisSummary" :key="ruleset" class="sigma-block mt-1">
                      <div class="sigma-ruleset">{{ ruleset }}</div>
                      <div class="flex flex-wrap gap-1 mt-1">
                        <span v-if="counts.critical" class="sigma-pill critical">🔴 Critical: {{ counts.critical }}</span>
                        <span v-if="counts.high"     class="sigma-pill high"    >🟠 High: {{ counts.high }}</span>
                        <span v-if="counts.medium"   class="sigma-pill medium"  >🟡 Medium: {{ counts.medium }}</span>
                        <span v-if="counts.low"      class="sigma-pill low"     >🟢 Low: {{ counts.low }}</span>
                      </div>
                    </div>
                  </div>
                </template>
              </div>

              <!-- MALWAREBAZAAR card -->
              <div v-if="activeHashResult.malwarebazaar && activeHashResult.malwarebazaar.queryStatus" class="card">
                <div class="card-head">
                  <span class="card-head-left">🦠 MalwareBazaar</span>
                  <div class="flex items-center gap-2">
                    <span v-if="activeHashResult.malwarebazaar.queryStatus==='ok'" class="mb-found-badge">✓ Found</span>
                    <span v-else class="mb-notfound-badge">✗ Not Found</span>
                    <a v-if="hashResultLinks.malwarebazaar" :href="hashResultLinks.malwarebazaar" target="_blank" rel="noopener" class="card-source-link">↗ MB</a>
                  </div>
                </div>
                <template v-if="activeHashResult.malwarebazaar.queryStatus === 'ok'">
                  <div v-if="activeHashResult.malwarebazaar.signature" class="kv">
                    <span class="kv-key">Signature</span>
                    <span class="kv-val" style="color:var(--red);font-weight:600">{{ activeHashResult.malwarebazaar.signature }}</span>
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
                  <div v-if="toArr(activeHashResult.malwarebazaar.tags).length" class="hash-tags">
                    <span v-for="tag in toArr(activeHashResult.malwarebazaar.tags)" :key="tag" class="hash-tag">{{ tag }}</span>
                  </div>
                </template>
                <div v-else class="kv mt-2">
                  <span class="kv-val" style="color:var(--muted);font-style:italic;font-size:0.68rem">
                    {{ activeHashResult.malwarebazaar.queryStatus === 'hash_not_found' ? 'This hash is not indexed in MalwareBazaar.' : activeHashResult.malwarebazaar.queryStatus }}
                  </span>
                </div>
              </div>

              <!-- THREATFOX card (hash mode) -->
              <div v-if="activeHashResult.threatfox" class="card">
                <div class="card-head">
                  <span class="card-head-left">🦊 ThreatFox</span>
                  <div class="flex items-center gap-2">
                    <span v-if="activeHashResult.threatfox.queryStatus === 'ok'" class="mb-found-badge">✓ Found</span>
                    <span v-else class="mb-notfound-badge">✗ {{ activeHashResult.threatfox.queryStatus || 'No Result' }}</span>
                    <a :href="'https://threatfox.abuse.ch/browse.php?search=ioc%3A'+(activeHashResult.virustotal.sha256||activeHashResult.virustotal.md5||'')" target="_blank" rel="noopener" class="card-source-link">↗ ThreatFox</a>
                  </div>
                </div>
                <template v-if="activeHashResult.threatfox.queryStatus === 'ok' && activeHashResult.threatfox.iocs && activeHashResult.threatfox.iocs.length">
                  <div v-if="activeHashResult.threatfox.iocs[0].malware" class="kv">
                    <span class="kv-key">Malware</span>
                    <span class="kv-val" style="color:var(--red);font-weight:600">{{ activeHashResult.threatfox.iocs[0].malware }}</span>
                  </div>
                  <div v-if="activeHashResult.threatfox.iocs[0].threatType" class="kv">
                    <span class="kv-key">Threat Type</span><span class="kv-val">{{ activeHashResult.threatfox.iocs[0].threatType }}</span>
                  </div>
                  <div v-if="activeHashResult.threatfox.iocs[0].malwareAlias" class="kv">
                    <span class="kv-key">Aliases</span>
                    <span class="kv-val" style="color:var(--text1);font-size:0.68rem">{{ activeHashResult.threatfox.iocs[0].malwareAlias }}</span>
                  </div>
                  <div v-if="activeHashResult.threatfox.iocs[0].confidenceLevel != null" class="kv">
                    <span class="kv-key">Confidence</span>
                    <span class="kv-val" :style="{color: activeHashResult.threatfox.iocs[0].confidenceLevel >= 75 ? 'var(--red)' : activeHashResult.threatfox.iocs[0].confidenceLevel >= 50 ? 'var(--orange)' : 'var(--yellow)', fontWeight:600}">
                      {{ activeHashResult.threatfox.iocs[0].confidenceLevel }}%
                    </span>
                  </div>
                  <div v-if="activeHashResult.threatfox.iocs[0].firstSeen" class="kv">
                    <span class="kv-key">First Seen</span><span class="kv-val">{{ activeHashResult.threatfox.iocs[0].firstSeen }}</span>
                  </div>
                  <div v-if="activeHashResult.threatfox.iocs[0].tags && activeHashResult.threatfox.iocs[0].tags.length" class="hash-tags mt-2">
                    <span v-for="tag in activeHashResult.threatfox.iocs[0].tags" :key="tag" class="hash-tag">{{ tag }}</span>
                  </div>
                  <div v-if="activeHashResult.threatfox.iocs.length > 1" class="mt-3">
                    <div class="vt-subsection-label">Associated IOCs ({{ activeHashResult.threatfox.iocs.length }})</div>
                    <div v-for="entry in activeHashResult.threatfox.iocs" :key="entry.ioc" class="kv mt-1">
                      <span class="kv-key" style="font-size:0.58rem">IOC</span>
                      <span class="kv-val" style="font-size:0.62rem;word-break:break-all;color:var(--text1)">{{ entry.ioc }}</span>
                    </div>
                  </div>
                </template>
                <div v-if="activeHashResult.threatfox.queryStatus !== 'ok'" class="kv mt-2">
                  <span class="kv-val" style="color:var(--muted);font-style:italic;font-size:0.68rem">
                    {{ activeHashResult.threatfox.queryStatus === 'no_results' ? 'No ThreatFox intelligence for this hash.' : activeHashResult.threatfox.queryStatus }}
                  </span>
                </div>
              </div>

            </div><!-- /cards grid -->

            <!-- Raw JSON panel -->
            <div class="json-panel mt-4">
              <button class="copy-btn" @click="copyHashJSON">COPY JSON</button>
              <pre><code v-html="highlightedHashJSON"></code></pre>
            </div>

          </div><!-- /hash-result-card -->
          <div v-else-if="allHashResults[activeHashIdx] && allHashResults[activeHashIdx].error" class="card">
            <div class="card-head">Error</div>
            <div style="color:var(--red)">{{ allHashResults[activeHashIdx].error }}</div>
          </div>
        </div>

        <!-- Hash Table view -->
        <div v-show="hashView==='table'">
          <results-table
            :visible-cols="visibleHashTableCols"
            :sorted-rows="sortedHashRows"
            :sort-col="hashSortCol"
            :sort-asc="hashSortAsc"
            :render-cell="renderHashTableCell"
            @sort="sortHashTable"
            @row-click="row => { activeHashIdx = row._idx; setHashView('cards'); }"
          ></results-table>
        </div>
      </div>
    </div>

  </div>
  `,
});