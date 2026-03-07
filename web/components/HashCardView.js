// components/HashCardView.js
// ─────────────────────────────────────────────────────────────────────────────
// Hash scan results — cards view, JSON panel, and table view wrapper.
// All state is read from composables; no props needed.
// ─────────────────────────────────────────────────────────────────────────────

import ResultsTable from './ResultsTable.js';

import {
    allHashResults, activeHashIdx,
    activeHashEntry, activeHashResult,
    hashResultLinks, signerDetailObj, signerIsRevoked, signerIsInvalid, vtNotFound,
    highlightedHashJSON,
    hashView, visibleHashTableCols, sortedHashRows,
    hashSortCol, hashSortAsc,
    riskDotColor, formatBytes, toArr,
    copyHashJSON, setHashView, sortHashTable, renderHashTableCell,
} from '../composables/useIOCScan.js';

const { defineComponent } = Vue;

export default defineComponent({
    name: 'HashCardView',
    components: { ResultsTable },

    setup() {
        return {
            allHashResults, activeHashIdx,
            activeHashEntry, activeHashResult,
            hashResultLinks, signerDetailObj, signerIsRevoked, signerIsInvalid, vtNotFound,
            highlightedHashJSON,
            hashView, visibleHashTableCols, sortedHashRows,
            hashSortCol, hashSortAsc,
            riskDotColor, formatBytes, toArr,
            copyHashJSON, setHashView, sortHashTable, renderHashTableCell,
        };
    },

    template: `
    <div>
      <!-- Hash chip tabs (multi-hash, cards view only) -->
      <div v-if="allHashResults.length > 1 && hashView==='cards'" class="flex flex-wrap gap-1 mb-4">
        <div v-for="(e, i) in allHashResults" :key="i"
             class="ip-tab" :class="{active: i===activeHashIdx}" @click="activeHashIdx=i">
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
              <div class="hash-card-title">
                {{ (activeHashResult.virustotal && (activeHashResult.virustotal.sha256 || activeHashResult.virustotal.sha1 || activeHashResult.virustotal.md5)) || allHashResults[activeHashIdx]?.hash || '—' }}
              </div>
              <div class="hash-card-meta">
                <span v-if="activeHashResult.riskLevel" :class="['risk-pill','risk-'+(activeHashResult.riskLevel)]">{{ activeHashResult.riskLevel }}</span>
                <span v-if="activeHashResult.hashType"  class="hash-type-badge">{{ activeHashResult.hashType }}</span>
                <span v-if="activeHashResult.virustotal && activeHashResult.virustotal.suggestedThreatLabel" class="hash-threat-label">{{ activeHashResult.virustotal.suggestedThreatLabel }}</span>
              </div>
            </div>
            <div class="flex gap-2" style="flex-shrink:0">
              <a v-if="hashResultLinks.virustotal && !vtNotFound" :href="hashResultLinks.virustotal"
                 target="_blank" rel="noopener" class="hash-source-link">↗ VT</a>
              <span v-else-if="vtNotFound" class="hash-source-link-na" title="Hash not found in VirusTotal">✗ VT</span>
              <a v-if="hashResultLinks.malwarebazaar && activeHashResult.malwarebazaar && activeHashResult.malwarebazaar.queryStatus === 'ok'"
                 :href="hashResultLinks.malwarebazaar" target="_blank" rel="noopener" class="hash-source-link">↗ MB</a>
              <span v-else-if="activeHashResult.malwarebazaar && activeHashResult.malwarebazaar.queryStatus && activeHashResult.malwarebazaar.queryStatus !== 'ok'"
                    class="hash-source-link-na" title="Hash not found in MalwareBazaar">✗ MB</span>
            </div>
          </div>

          <!-- Hash Values row -->
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
                  <a v-if="hashResultLinks.virustotal" :href="hashResultLinks.virustotal"
                     target="_blank" rel="noopener" class="card-source-link">↗ VirusTotal</a>
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
                  <a v-if="hashResultLinks.malwarebazaar" :href="hashResultLinks.malwarebazaar"
                     target="_blank" rel="noopener" class="card-source-link">↗ MB</a>
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

            <!-- THREATFOX card -->
            <div v-if="activeHashResult.threatfox" class="card">
              <div class="card-head">
                <span class="card-head-left">🦊 ThreatFox</span>
                <div class="flex items-center gap-2">
                  <span v-if="activeHashResult.threatfox.queryStatus === 'ok'" class="mb-found-badge">✓ Found</span>
                  <span v-else class="mb-notfound-badge">✗ {{ activeHashResult.threatfox.queryStatus || 'No Result' }}</span>
                  <a :href="'https://threatfox.abuse.ch/browse.php?search=ioc%3A'+(activeHashResult.virustotal?.sha256||activeHashResult.virustotal?.md5||'')"
                     target="_blank" rel="noopener" class="card-source-link">↗ ThreatFox</a>
                </div>
              </div>
              <template v-if="activeHashResult.threatfox.queryStatus === 'ok' && activeHashResult.threatfox.iocs && activeHashResult.threatfox.iocs.length">
                <div v-if="activeHashResult.threatfox.iocs[0].malware" class="kv">
                  <span class="kv-key">Malware</span>
                  <span class="kv-val" style="color:var(--red);font-weight:600">{{ activeHashResult.threatfox.iocs[0].malware }}</span>
                </div>
                <div v-if="activeHashResult.threatfox.iocs[0].threatType" class="kv">
                  <span class="kv-key">Threat Type</span>
                  <span class="kv-val">{{ activeHashResult.threatfox.iocs[0].threatType }}</span>
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
                  <span class="kv-key">First Seen</span>
                  <span class="kv-val">{{ activeHashResult.threatfox.iocs[0].firstSeen }}</span>
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
            <button class="copy-btn" @click="copyHashJSON(activeHashResult)">COPY JSON</button>
            <pre><code v-html="highlightedHashJSON"></code></pre>
          </div>

        </div><!-- /hash-result-card -->

        <!-- Error state -->
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
    `,
});