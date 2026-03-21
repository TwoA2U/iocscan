// main.js
// ─────────────────────────────────────────────────────────────────────────────
// Application entry point.
// Dynamically imports the root shell so startup/import failures can be caught
// and surfaced in-page instead of leaving a blank screen.
// ─────────────────────────────────────────────────────────────────────────────

import { loadManifests } from './composables/useIntegrations.js?v=11';

const { createApp } = Vue;

function renderBootError(err) {
    const root = document.getElementById('app');
    if (!root) return;
    const message = err && err.stack ? err.stack : String(err);
    root.innerHTML = `
      <div style="min-height:100vh;background:#09090d;color:#f0f1f5;display:flex;align-items:center;justify-content:center;padding:24px;font-family:monospace">
        <div style="width:min(900px,100%);background:#0f0f14;border:1px solid rgba(252,129,129,0.28);border-left:3px solid #fc8181;border-radius:10px;padding:20px;box-shadow:0 12px 40px rgba(0,0,0,0.4)">
          <div style="font:700 12px sans-serif;letter-spacing:.18em;text-transform:uppercase;color:#fc8181;margin-bottom:12px">Application Error</div>
          <pre style="white-space:pre-wrap;word-break:break-word;margin:0;color:#f0f1f5;font-size:12px;line-height:1.6">${message.replace(/[&<>]/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[ch]))}</pre>
        </div>
      </div>
    `;
}

window.addEventListener('error', event => {
    renderBootError(event.error || event.message || 'Unknown error');
});

window.addEventListener('unhandledrejection', event => {
    renderBootError(event.reason || 'Unhandled promise rejection');
});

async function boot() {
    try {
        const mod = await import('./components/AppShell.js?v=11');
        const app = createApp(mod.default);
        app.config.errorHandler = (err) => {
            console.error(err);
            renderBootError(err);
        };
        app.mount('#app');
        loadManifests();
    } catch (err) {
        console.error(err);
        renderBootError(err);
    }
}

boot();
