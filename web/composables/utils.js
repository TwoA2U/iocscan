// composables/utils.js
// ─────────────────────────────────────────────────────────────────────────────
// Shared utility functions used by both useIPResults.js and useHashResults.js.
//
// Extracted to eliminate duplication:
//   highlight  — was `highlight` in useIPResults.js and `_highlight` in useHashResults.js
//   download   — was `_download` duplicated in both files
//   escapeHTML — new; used by highlight() to prevent XSS via API-derived string values
// ─────────────────────────────────────────────────────────────────────────────

// escapeHTML sanitises a string for safe insertion into HTML.
// Applied to all non-key string values produced by highlight() so that
// malicious content in API responses (e.g. ISP names, malware family names)
// cannot inject HTML into the JSON viewer panels.
export function escapeHTML(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// highlight produces syntax-highlighted HTML from a JSON string.
// String values (non-keys) are HTML-escaped before insertion to prevent XSS.
export function highlight(json) {
    return json.replace(
        /("(?:\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*"(\s*:)?|true|false|null|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
        m => {
            if (/^"/.test(m)) {
                // Key token (ends with :) — safe, these are always field names
                if (/:$/.test(m)) return `<span class="j-k">${m}</span>`;
                // String value token — escape before inserting into DOM
                return `<span class="j-s">${escapeHTML(m)}</span>`;
            }
            if (/true|false/.test(m)) return `<span class="j-b">${m}</span>`;
            if (/null/.test(m))       return `<span class="j-0">${m}</span>`;
            return `<span class="j-n">${m}</span>`;
        }
    );
}

// download triggers a file download in the browser for the given content.
export function download(content, filename, type) {
    const blob = new Blob([content], { type });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
}