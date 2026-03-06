// main.js
// ─────────────────────────────────────────────────────────────────────────────
// Application entry point.
// Imports the root IOCScanner component and mounts the Vue 3 app to #app.
//
// All module imports use relative paths compatible with native ES modules
// loaded directly by the browser — no bundler required.
// ─────────────────────────────────────────────────────────────────────────────

import IOCScanner from './components/IOCScanner.js';

const { createApp } = Vue;

createApp(IOCScanner).mount('#app');