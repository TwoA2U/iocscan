// main.js
// ─────────────────────────────────────────────────────────────────────────────
// Application entry point.
// Imports the root IOCScanner component, mounts the Vue 3 app, then
// loads integration manifests from /api/integrations in the background.
//
// loadManifests() is called after mount so the UI is interactive immediately
// while the manifest fetch is in-flight. All components that consume manifests
// read from the reactive refs in useIntegrations.js and re-render automatically
// once the fetch completes (typically <50ms on localhost).
//
// All module imports use relative paths compatible with native ES modules
// loaded directly by the browser — no bundler required.
// ─────────────────────────────────────────────────────────────────────────────

import IOCScanner      from './components/IOCScanner.js';
import { loadManifests } from './composables/useIntegrations.js';

const { createApp } = Vue;

createApp(IOCScanner).mount('#app');

// Load integration manifests after mount — non-blocking.
// useIntegrations.js is idempotent so this is safe to call multiple times.
loadManifests();