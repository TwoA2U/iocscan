// components/ColumnDrawer.js
// ─────────────────────────────────────────────────────────────────────────────
// The ⚙ COLUMNS button and its overlay + sliding drawer panel.
// Handles both IP mode (sections with fields) and Hash mode (dynamic columns).
// All state lives in composables; this component is purely presentational.
// ─────────────────────────────────────────────────────────────────────────────

import {
    colVisible, fieldVisible,
    hashDynCols,
    toggleCol, toggleSection, toggleField,
    toggleHashCol, toggleHashSection, setAllCols,
} from '../composables/useColumnVisibility.js';

import {
    currentIOCMode, colBadge, ipDrawerSections, hashDrawerSections,
    colDrawerOpen, openColDrawer, closeColDrawer,
} from '../composables/useIOCScan.js';

const { defineComponent } = Vue;

export default defineComponent({
    name: 'ColumnDrawer',

    setup() {
        return {
            // State
            colVisible, fieldVisible, hashDynCols,
            currentIOCMode, colBadge, ipDrawerSections, hashDrawerSections,
            colDrawerOpen,
            // Actions
            openColDrawer, closeColDrawer,
            toggleCol, toggleSection, toggleField,
            toggleHashCol, toggleHashSection,
            setAllColsProxy(visible) { setAllCols(visible, currentIOCMode.value); },
        };
    },

    template: `
    <div class="col-drawer-wrap">
      <!-- Trigger button -->
      <button class="action-btn flex items-center gap-2" @click="openColDrawer">
        ⚙ COLUMNS
        <span style="color:#38bdf8;font-size:0.62rem">{{ colBadge }}</span>
      </button>

      <!-- Click-away overlay (z-index below drawer) -->
      <div
        class="col-overlay"
        :class="{ on: colDrawerOpen }"
        @click="closeColDrawer"
      ></div>

      <!-- Drawer panel (z-index above overlay) -->
      <div class="col-drawer" :class="{ open: colDrawerOpen }">

        <!-- Header -->
        <div class="flex items-center justify-between px-4 py-3 border-b" style="border-color:#1e2d42">
          <span class="text-xs font-bold tracking-widest uppercase" style="color:#e2e8f0">Columns</span>
          <button
            @click="closeColDrawer"
            style="background:none;border:none;color:#4d6480;font-size:1.1rem;cursor:pointer"
          >✕</button>
        </div>

        <!-- Scrollable column list -->
        <div class="flex-1 overflow-y-auto">

          <!-- IP Mode sections -->
          <template v-if="currentIOCMode === 'ip' && ipDrawerSections.length">
            <template v-for="sec in ipDrawerSections" :key="sec.key">
              <div
                class="col-section-head col-row-top"
                @click="sec.fields.length ? toggleSection(sec.key) : toggleCol(sec.key)"
              >
                <span>{{ sec.icon }} {{ sec.label }}</span>
                <button
                  class="tog"
                  :class="{ on: colVisible[sec.key] }"
                  @click.stop="sec.fields.length ? toggleSection(sec.key) : toggleCol(sec.key)"
                ></button>
              </div>
              <div
                v-for="f in sec.fields"
                :key="f.key"
                class="col-row"
                @click="toggleField(f.key)"
              >
                <span class="col-row-label">{{ f.label }}</span>
                <button
                  class="tog"
                  :class="{ on: fieldVisible[f.key] }"
                  @click.stop="toggleField(f.key)"
                ></button>
              </div>
            </template>
          </template>

          <!-- Hash Mode sections -->
          <template v-else-if="currentIOCMode === 'hash' && hashDrawerSections.length">
            <template v-for="sec in hashDrawerSections" :key="sec.key">
              <div class="col-section-head col-row-top" @click="toggleHashSection(sec.key)">
                <span>{{ sec.icon }} {{ sec.label }}</span>
                <button
                  class="tog"
                  :class="{ on: sec.allOn }"
                  @click.stop="toggleHashSection(sec.key)"
                ></button>
              </div>
              <div
                v-for="c in sec.cols"
                :key="c.key"
                class="col-row"
                @click="toggleHashCol(c.key)"
              >
                <span class="col-row-label">{{ c.label }}</span>
                <button
                  class="tog"
                  :class="{ on: c.visible }"
                  @click.stop="toggleHashCol(c.key)"
                ></button>
              </div>
            </template>
          </template>

          <!-- No results yet -->
          <p
            v-else
            class="text-center py-6 text-xs"
            style="color:#2e4060"
          >Run a scan first to see<br>available columns.</p>

        </div>

        <!-- Show All / Hide All footer -->
        <div class="flex gap-2 p-3 border-t" style="border-color:#1e2d42">
          <button class="action-btn flex-1" @click="setAllColsProxy(true)">Show All</button>
          <button class="action-btn flex-1" @click="setAllColsProxy(false)">Hide All</button>
        </div>

      </div>
    </div>
  `,
});