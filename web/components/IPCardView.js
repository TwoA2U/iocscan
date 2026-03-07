// components/IPCardView.js
// ─────────────────────────────────────────────────────────────────────────────
// IP scan results — cards view, JSON panel, and table view wrapper.
// All state is read from composables; no props needed.
// ─────────────────────────────────────────────────────────────────────────────

import ResultsTable from './ResultsTable.js';

import {
    allResults, activeIdx, activeResultEntry, activeResultIP, activeResult,
    networkRows, highlightedJSON,
    colVisible, fieldVisible,
    currentView, visibleTableCols, sortedTableRows,
    tableSortCol, tableSortAsc,
    abuseColor, vtStatPart, riskDotColor, yn,
    copyJSON, setView, switchTab, switchToCard, sortTable, renderTableCell,
} from '../composables/useIOCScan.js';

const { defineComponent } = Vue;

export default defineComponent({
    name: 'IPCardView',
    components: { ResultsTable },

    setup() {
        return {
            allResults, activeIdx, activeResultEntry, activeResultIP, activeResult,
            networkRows, highlightedJSON,
            colVisible, fieldVisible,
            currentView, visibleTableCols, sortedTableRows,
            tableSortCol, tableSortAsc,
            abuseColor, vtStatPart, riskDotColor, yn,
            copyJSON, setView, switchTab, switchToCard, sortTable, renderTableCell,
        };
    },

    template: `
    <div>
      <!-- IP chip tabs (multi-IP, cards view only) -->
      <div v-if="allResults.length > 1 && currentView==='cards'" class="flex flex-wrap gap-1 mb-4">
        <div v-for="(r, i) in allResults" :key="r.ip"
             class="ip-tab" :class="{active: i===activeIdx}" @click="switchTab(i)">
          <span class="ip-tab-dot" :style="{background: riskDotColor(r.result ? r.result.riskLevel : null)}"></span>
          {{ r.ip }}
        </div>
      </div>

      <!-- Cards view -->
      <div v-show="currentView==='cards'" id="cardsView">
        <div v-if="activeResult">
          <!-- Risk pill -->
          <div v-if="colVisible.risk" class="mb-4">
            <span :class="['risk-pill', 'risk-' + (activeResult.riskLevel||'CLEAN')]">
              {{ activeResult.riskLevel || 'CLEAN' }}
            </span>
            <span style="font-family:'JetBrains Mono',monospace;font-size:0.8rem;color:#e2e8f0;margin-left:12px">
              {{ activeResultIP }}
            </span>
          </div>

          <div class="cards">
            <!-- Network card -->
            <div v-if="colVisible.network && networkRows.length" class="card" id="card-network">
              <div class="card-head">
                <span class="card-head-left">🌍 Network Info</span>
                <a :href="'https://api.ipapi.is/?q='+activeResultIP" target="_blank" rel="noopener"
                   class="card-source-link">↗ ipapi.is</a>
              </div>
              <div v-for="[k,v,fkey] in networkRows" :key="k"
                   class="kv" :data-field="fkey" v-show="!fkey || fieldVisible[fkey]">
                <span class="kv-key">{{ k }}</span><span class="kv-val">{{ v }}</span>
              </div>
            </div>

            <!-- AbuseIPDB card -->
            <div v-if="colVisible.abuse && activeResult.abuseipdb && activeResult.abuseipdb.confidenceScore != null"
                 class="card" id="card-abuse">
              <div class="card-head">
                <span class="card-head-left">🚨 AbuseIPDB</span>
                <a :href="'https://www.abuseipdb.com/check/'+activeResultIP" target="_blank" rel="noopener"
                   class="card-source-link">↗ AbuseIPDB</a>
              </div>
              <div class="kv" v-show="fieldVisible['ab-score']">
                <span class="kv-key">Confidence</span>
                <span class="kv-val" :style="{color: abuseColor(activeResult.abuseipdb.confidenceScore), fontWeight:600}">
                  {{ activeResult.abuseipdb.confidenceScore }}%
                </span>
              </div>
              <div class="meter" v-show="fieldVisible['ab-meter']">
                <div class="meter-bar" :style="{width: activeResult.abuseipdb.confidenceScore+'%', background: abuseColor(activeResult.abuseipdb.confidenceScore)}"></div>
              </div>
              <div class="kv" v-show="fieldVisible['ab-reports']">
                <span class="kv-key">Total Reports</span>
                <span class="kv-val">{{ activeResult.abuseipdb.totalReports ?? '—' }}</span>
              </div>
              <div class="kv" v-show="fieldVisible['ab-lastreport']">
                <span class="kv-key">Last Reported</span>
                <span class="kv-val">{{ activeResult.abuseipdb.lastReportedAt || '—' }}</span>
              </div>
            </div>

            <!-- VirusTotal card -->
            <div v-if="colVisible.vt && activeResult.virustotal && activeResult.virustotal.malicious != null"
                 class="card" id="card-vt">
              <div class="card-head">
                <span class="card-head-left">🧪 VirusTotal</span>
                <a :href="'https://www.virustotal.com/gui/ip-address/'+activeResultIP" target="_blank" rel="noopener"
                   class="card-source-link">↗ VirusTotal</a>
              </div>
              <div class="kv" v-show="fieldVisible['vt-summary']">
                <span class="kv-key">Summary (S/U/H)</span>
                <span class="kv-val">{{ activeResult.virustotal ? (activeResult.virustotal.suspicious ?? 0) + '/' + (activeResult.virustotal.undetected ?? 0) + '/' + (activeResult.virustotal.harmless ?? 0) : '—' }}</span>
              </div>
              <div class="vt-pills">
                <span v-show="fieldVisible['vt-malicious']"  class="vt-pill mal">🔴 Malicious: {{ activeResult.virustotal.malicious }}</span>
                <span v-show="fieldVisible['vt-suspicious']" class="vt-pill sus">🟡 Suspicious: {{ activeResult.virustotal.suspicious ?? 0 }}</span>
                <span v-show="fieldVisible['vt-harmless']"   class="vt-pill ok">🟢 Harmless: {{ vtStatPart(2) }}</span>
                <span v-show="fieldVisible['vt-undetected']" class="vt-pill unk">⬜ Undetected: {{ vtStatPart(1) }}</span>
              </div>
            </div>

            <!-- ThreatFox card -->
            <div v-if="activeResult.threatfox" class="card" id="card-tf">
              <div class="card-head">
                <span class="card-head-left">🦊 ThreatFox</span>
                <div class="flex items-center gap-2">
                  <span v-if="activeResult.threatfox.queryStatus === 'ok'" class="mb-found-badge">✓ Found</span>
                  <span v-else class="mb-notfound-badge">✗ {{ activeResult.threatfox.queryStatus || 'No Result' }}</span>
                  <a :href="'https://threatfox.abuse.ch/browse.php?search=ioc%3A'+activeResultIP"
                     target="_blank" rel="noopener" class="card-source-link">↗ ThreatFox</a>
                </div>
              </div>
              <template v-if="activeResult.threatfox.queryStatus === 'ok'">
                <div v-if="activeResult.threatfox.malware" class="kv">
                  <span class="kv-key">Malware</span>
                  <span class="kv-val" style="color:var(--red);font-weight:600">{{ activeResult.threatfox.malware }}</span>
                </div>
                <div v-if="activeResult.threatfox.threatType" class="kv">
                  <span class="kv-key">Threat Type</span>
                  <span class="kv-val">{{ activeResult.threatfox.threatType }}</span>
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
                  <span class="kv-key">First Seen</span>
                  <span class="kv-val">{{ activeResult.threatfox.firstSeen }}</span>
                </div>
                <div v-if="activeResult.threatfox.lastSeen" class="kv">
                  <span class="kv-key">Last Seen</span>
                  <span class="kv-val">{{ activeResult.threatfox.lastSeen }}</span>
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
                  <div v-for="s in activeResult.threatfox.malwareSamples" :key="s.sha256_hash"
                       class="kv mt-1" style="align-items:flex-start">
                    <span class="kv-key" style="font-size:0.58rem;padding-top:2px">SHA256</span>
                    <span class="kv-val" style="font-size:0.58rem;word-break:break-all">
                      <a v-if="s.malware_bazaar" :href="s.malware_bazaar" target="_blank" rel="noopener"
                         style="color:var(--accent);text-decoration:none">{{ s.sha256_hash }}</a>
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
            <button class="copy-btn" @click="copyJSON(activeResult)">COPY JSON</button>
            <pre><code v-html="highlightedJSON"></code></pre>
          </div>
        </div>

        <!-- Error state -->
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
    `,
});