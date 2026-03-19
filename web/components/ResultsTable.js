// components/ResultsTable.js
// ─────────────────────────────────────────────────────────────────────────────
// Generic sortable table used by both IP mode and Hash mode.
// Props:
//   visibleCols  — array of { key, label }
//   sortedRows   — pre-sorted data rows (array of objects)
//   sortCol      — currently sorted column key (string)
//   sortAsc      — sort direction (boolean)
//   renderCell   — function(col, row, index) → HTML string
//   clickable    — boolean, adds clickable row class/handler (default true)
// Emits:
//   sort(colKey)         — user clicked a header
//   row-click(row)       — user clicked a data row
// ─────────────────────────────────────────────────────────────────────────────

const { defineComponent } = Vue;

export default defineComponent({
    name: 'ResultsTable',
    props: {
        visibleCols: { type: Array,    required: true },
        sortedRows:  { type: Array,    required: true },
        sortCol:     { type: String,   default: '' },
        sortAsc:     { type: Boolean,  default: true },
        renderCell:  { type: Function, required: true },
        clickable:   { type: Boolean,  default: true },
    },
    emits: ['sort', 'row-click'],
    template: `
    <div class="overflow-x-auto">
      <table class="ioc-table">
        <thead>
          <tr>
            <th
              v-for="col in visibleCols"
              :key="col.key"
              :class="{ sorted: sortCol === col.key }"
              @click="$emit('sort', col.key)"
            >
              {{ col.label }}
              <span class="sort-icon">{{
                sortCol === col.key ? (sortAsc ? '▲' : '▼') : '⇅'
              }}</span>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="(row, i) in sortedRows"
            :key="row._ip || row.hash || row._idx || i"
            :class="{ clickable: clickable }"
            @click="clickable && $emit('row-click', row)"
          >
            <td
              v-for="col in visibleCols"
              :key="col.key"
              v-html="renderCell(col, row, i)"
            ></td>
          </tr>
        </tbody>
      </table>
    </div>
  `,
});