// components/ScanSettings.js
// ─────────────────────────────────────────────────────────────────────────────
// Legacy placeholder component.
// API keys are now managed in SettingsPage via authenticated server-side storage.
// ─────────────────────────────────────────────────────────────────────────────

const { defineComponent } = Vue;

export default defineComponent({
    name: 'ScanSettings',

    template: `
    <div class="border p-5 mb-6 relative" style="border-color:#1e2d42;background:#0d1320">
      <span class="absolute -top-2 left-3 px-2 text-xs font-bold tracking-widest uppercase"
            style="background:#0d1320;color:#4d6480;font-size:0.58rem">API Keys</span>
      <p class="text-sm" style="color:#9ca3b0">
        API key management moved to the authenticated Settings page.
      </p>
    </div>
    `,
});
