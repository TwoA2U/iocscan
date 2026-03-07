// web/utils.js
// ─────────────────────────────────────────────────────────────────────────────
// Shared utility functions used across composables.
// Uses native ES modules — no bundler required.
// ─────────────────────────────────────────────────────────────────────────────

// highlightJSON applies syntax-highlight spans to a JSON string for display
// inside a <pre v-html="..."> block. Shared by useIPResults and useHashResults
// to avoid duplication.
export function highlightJSON(json) {
    return json.replace(
        /(\"(?:\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*\"(\s*:)?|true|false|null|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
        m => {
            if (/^"/.test(m)) return /:$/.test(m) ? `<span class="j-k">${m}</span>` : `<span class="j-s">${m}</span>`;
            if (/true|false/.test(m)) return `<span class="j-b">${m}</span>`;
            if (/null/.test(m)) return `<span class="j-0">${m}</span>`;
            return `<span class="j-n">${m}</span>`;
        }
    );
}