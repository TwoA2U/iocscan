// components/IntegrationCard.js
// ─────────────────────────────────────────────────────────────────────────────
// Generic card renderer driven entirely by an integration's Manifest.Card
// definition. Replaces the per-vendor card sections in IPCardView.js and
// HashCardView.js with a single data-driven component.
//
// Props:
//   manifest  — Manifest object from useIntegrations (required)
//   result    — map[string]any from ScanResult.results[manifest.name]
//               Pass null/undefined to render an error or empty state.
//   ioc       — the scanned indicator string (for link template substitution)
//   error     — optional error string when this integration failed
//
// Supports all FieldType values declared in integration.go:
//   string | number | bool | badge | score_bar | tags | link
//
// Uses Vue 3 GLOBAL build (window.Vue) — no bundler required.
// Uses CSS variables from index.html :root block — no external stylesheet.
// ─────────────────────────────────────────────────────────────────────────────

import { scoreBarColor, badgeColor, buildLinkUrl } from '../composables/useIntegrations.js';

const { defineComponent, computed } = Vue;

export default defineComponent({
    name: 'IntegrationCard',

    props: {
        manifest: { type: Object,  required: true },
        result:   { type: Object,  default: null  },
        ioc:      { type: String,  default: ''    },
        error:    { type: String,  default: ''    },
    },

    setup(props) {
        // Build the header link URL by substituting {ioc} in the template.
        const headerLink = computed(() =>
            buildLinkUrl(props.manifest?.card?.linkTemplate ?? '', props.ioc)
        );

        // Ordered visible fields: only include fields that have a non-null,
        // non-empty-string value in the result. Skipping empties keeps cards
        // compact and avoids rows like "Signer: —" for every clean file.
        const visibleFields = computed(() => {
            const fields = props.manifest?.card?.fields ?? [];
            if (!props.result) return [];
            return fields.filter(field => {
                const val = props.result[field.key];
                if (val === null || val === undefined) return false;
                if (typeof val === 'string'  && val === '') return false;
                if (Array.isArray(val) && val.length === 0) return false;
                return true;
            });
        });

        // hasData is true when there is at least one visible field to render.
        const hasData = computed(() =>
            visibleFields.value.length > 0 || !!props.error
        );

        // ── Per-field rendering helpers ───────────────────────────────────────

        function fieldColor(field, val) {
            switch (field.type) {
                case 'score_bar': return scoreBarColor(field.thresholds, val);
                case 'badge':     return badgeColor(field.colors, val);
                case 'bool':      return val ? (field.trueColor  || '#34d399')
                    : (field.falseColor || '#94a3b8');
                default:          return 'var(--text2)';
            }
        }

        function fieldLabel(field, val) {
            if (field.type === 'bool') {
                return val ? (field.trueLabel  || 'Yes')
                    : (field.falseLabel || 'No');
            }
            return null; // use raw value rendering for other types
        }

        // Format a field value as a display string for types that render as text.
        function displayValue(field, val) {
            if (val === null || val === undefined) return '—';
            if (field.type === 'number') return String(val);
            if (field.type === 'string') return String(val);
            if (field.type === 'link')   return String(val);
            return String(val);
        }

        return {
            headerLink,
            visibleFields,
            hasData,
            fieldColor,
            fieldLabel,
            displayValue,
            scoreBarColor,
            badgeColor,
        };
    },

    template: `
<div v-if="hasData" class="card">

  <!-- ── Card header ───────────────────────────────────────────────────── -->
  <div class="card-head">
    <span class="card-head-left">
      {{ manifest.icon }} {{ manifest.card.title }}
    </span>
    <a v-if="headerLink && !error"
       :href="headerLink"
       target="_blank"
       rel="noopener noreferrer"
       class="card-source-link">
      {{ manifest.card.linkLabel || '↗' }}
    </a>
  </div>

  <!-- ── Error state ───────────────────────────────────────────────────── -->
  <div v-if="error" class="kv" style="padding-top:8px">
    <span class="kv-val" style="color:var(--red);font-size:0.68rem;font-style:italic">
      ⚠ {{ error }}
    </span>
  </div>

  <!-- ── Field rows ────────────────────────────────────────────────────── -->
  <template v-else>
    <div
      v-for="field in visibleFields"
      :key="field.key"
      class="kv"
    >
      <span class="kv-key">{{ field.label }}</span>

      <!-- string / number -->
      <span
        v-if="field.type === 'string' || field.type === 'number'"
        class="kv-val"
      >{{ displayValue(field, result[field.key]) }}</span>

      <!-- bool -->
      <span
        v-else-if="field.type === 'bool'"
        class="kv-val"
        :style="{ color: fieldColor(field, result[field.key]), fontWeight: 600 }"
      >{{ fieldLabel(field, result[field.key]) }}</span>

      <!-- badge -->
      <span
        v-else-if="field.type === 'badge'"
        class="kv-val"
        :style="{ color: fieldColor(field, result[field.key]), fontWeight: 600 }"
      >{{ result[field.key] }}</span>

      <!-- score_bar -->
      <span v-else-if="field.type === 'score_bar'" class="kv-val" style="width:100%">
        <span :style="{ color: fieldColor(field, result[field.key]), fontWeight: 600 }">
          {{ result[field.key] }}%
        </span>
        <div class="meter" style="margin-top:4px">
          <div
            class="meter-bar"
            :style="{
              width: Math.min(100, Math.max(0, Number(result[field.key]))) + '%',
              background: fieldColor(field, result[field.key])
            }"
          ></div>
        </div>
      </span>

      <!-- tags -->
      <span v-else-if="field.type === 'tags'" class="kv-val" style="text-align:right">
        <span
          v-for="tag in (Array.isArray(result[field.key]) ? result[field.key] : [])"
          :key="tag"
          class="hash-tag"
          style="margin-left:4px"
        >{{ tag }}</span>
        <span
          v-if="!result[field.key] || result[field.key].length === 0"
          style="color:var(--dim);font-style:italic"
        >—</span>
      </span>

      <!-- link -->
      <span v-else-if="field.type === 'link'" class="kv-val">
        <a
          :href="result[field.key]"
          target="_blank"
          rel="noopener noreferrer"
          style="color:var(--accent);text-decoration:none;font-size:0.7rem"
        >↗ {{ result[field.key] }}</a>
      </span>

      <!-- fallback for unknown types -->
      <span v-else class="kv-val">{{ result[field.key] }}</span>

    </div><!-- /v-for field -->
  </template>

</div><!-- /card -->

<!-- Render nothing if no data and no error (integration silently skipped) -->
`,
});