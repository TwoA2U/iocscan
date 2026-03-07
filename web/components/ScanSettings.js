// components/ScanSettings.js
// ─────────────────────────────────────────────────────────────────────────────
// API key input panel. Renders the four key fields (VirusTotal, AbuseIPDB,
// ipapi.is, abuse.ch). Binds directly to the shared `keys` reactive object
// imported from useIOCScan — no props or emits needed.
// ─────────────────────────────────────────────────────────────────────────────

import { keys } from '../composables/useIOCScan.js';

const { defineComponent } = Vue;

export default defineComponent({
    name: 'ScanSettings',

    setup() {
        return { keys };
    },

    template: `
    <div class="border p-5 mb-6 relative" style="border-color:#1e2d42;background:#0d1320">
      <span class="absolute -top-2 left-3 px-2 text-xs font-bold tracking-widest uppercase"
            style="background:#0d1320;color:#4d6480;font-size:0.58rem">API Keys</span>
      <div class="grid gap-4" style="grid-template-columns:repeat(auto-fit,minmax(220px,1fr))">
        <div>
          <label class="block text-xs font-bold tracking-widest uppercase mb-2"
                 style="color:#4d6480;font-size:0.58rem">VirusTotal</label>
          <input type="password" v-model="keys.vt" class="key-input"
                 placeholder="Required for complex mode…">
        </div>
        <div>
          <label class="block text-xs font-bold tracking-widest uppercase mb-2"
                 style="color:#4d6480;font-size:0.58rem">AbuseIPDB</label>
          <input type="password" v-model="keys.abuse" class="key-input"
                 placeholder="Required for complex mode…">
        </div>
        <div>
          <label class="block text-xs font-bold tracking-widest uppercase mb-2"
                 style="color:#4d6480;font-size:0.58rem">
            IPAPI.IS <span style="color:#2e4060">(optional)</span>
          </label>
          <input type="password" v-model="keys.ipapi" class="key-input"
                 placeholder="Leave blank for free tier…">
        </div>
        <div>
          <label class="block text-xs font-bold tracking-widest uppercase mb-2"
                 style="color:#4d6480;font-size:0.58rem">
            abuse.ch <span style="color:#2e4060">(optional)</span>
          </label>
          <input type="password" v-model="keys.abusech" class="key-input"
                 placeholder="Used for MalwareBazaar + ThreatFox…">
        </div>
      </div>
    </div>
    `,
});