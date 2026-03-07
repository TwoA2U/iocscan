// composables/useScanHistory.js
// ─────────────────────────────────────────────────────────────────────────────
// Scan history state and helpers — last 20 scans with dedup, re-scan support.
// Uses Vue 3 GLOBAL build (window.Vue) — no bundler required.
// ─────────────────────────────────────────────────────────────────────────────

const { reactive } = Vue;

export const scanHist = reactive([]);

// addHist records or updates a scan entry. Duplicate IOCs update in-place
// (risk refreshed, lastSeen updated, scanCount incremented) so the history
// list stays at most 20 entries.
export function addHist(ioc, risk) {
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const existing = scanHist.findIndex(h => h.ip === ioc);
    if (existing !== -1) {
        scanHist[existing].risk      = risk;
        scanHist[existing].lastSeen  = time;
        scanHist[existing].scanCount = (scanHist[existing].scanCount || 1) + 1;
    } else {
        scanHist.unshift({ ip: ioc, risk, time, lastSeen: time, scanCount: 1 });
        if (scanHist.length > 20) scanHist.pop();
    }
}

export function clearHistory() {
    scanHist.splice(0, scanHist.length);
}

// reScan is wired up in useIOCScan.js where doIPScan is available,
// so we export a ref that useIOCScan.js will populate at init time.
// This avoids a circular dependency between the two composables.
let _reScanFn = null;

export function registerReScan(fn) { _reScanFn = fn; }

export function reScan(ioc) {
    if (_reScanFn) _reScanFn(ioc);
}