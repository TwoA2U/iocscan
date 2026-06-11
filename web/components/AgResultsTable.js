// components/AgResultsTable.js
// AG Grid Community wrapper for IOC result tables.

const { defineComponent } = Vue;

function normalizeValue(value) {
  if (value == null || value === "—") return "";
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return value;
}

export default defineComponent({
  name: "AgResultsTable",
  props: {
    visibleCols: { type: Array, required: true },
    rows: { type: Array, required: true },
    renderCell: { type: Function, required: true },
    getValue: { type: Function, default: null },
    clickable: { type: Boolean, default: true },
  },
  emits: ["row-click"],
  data() {
    return {
      gridApi: null,
      quickFilter: "",
      gridReady: false,
    };
  },
  computed: {},
  mounted() {
    this.initGrid();
  },
  beforeUnmount() {
    if (this.gridApi) this.gridApi.destroy();
  },
  watch: {
    visibleCols: {
      deep: true,
      handler() {
        this.refreshColumns();
      },
    },
    rows: {
      deep: true,
      handler() {
        this.refreshRows();
      },
    },
    quickFilter(value) {
      if (this.gridApi) this.gridApi.setGridOption("quickFilterText", value);
    },
  },
  methods: {
    canUseAgGrid() {
      return typeof window !== "undefined" && window.agGrid && this.$refs.grid;
    },
    rawValue(col, row, index) {
      if (this.getValue)
        return normalizeValue(this.getValue(row, col.key, index));
      if (typeof col.get === "function")
        return normalizeValue(col.get(row, index));
      return normalizeValue(row?.[col.key]);
    },
    buildColumnDefs() {
      return this.visibleCols.map((col) => ({
        colId: col.key,
        headerName: col.label || col.key,
        field: col.key,
        sortable: true,
        resizable: true,
        filter: "agTextColumnFilter",
        floatingFilter: false,
        minWidth: col.key === "#" ? 82 : 150,
        maxWidth: col.key === "#" ? 100 : undefined,
        valueGetter: (params) =>
          this.rawValue(col, params.data, params.node?.rowIndex ?? 0),
        cellRenderer: (params) =>
          this.renderCell(col, params.data, params.node?.rowIndex ?? 0),
      }));
    },
    initGrid() {
      if (!this.canUseAgGrid) return;
      const options = {
        columnDefs: this.buildColumnDefs(),
        rowData: this.rows,
        defaultColDef: {
          sortable: true,
          resizable: true,
          filter: "agTextColumnFilter",
          floatingFilter: false,
        },
        suppressCellFocus: true,
        animateRows: false,
        rowSelection: "single",
        domLayout: "autoHeight",
        quickFilterText: this.quickFilter,
        onRowClicked: (event) => {
          if (this.clickable) this.$emit("row-click", event.data);
        },
      };
      this.gridApi = window.agGrid.createGrid(this.$refs.grid, options);
      this.gridReady = true;
    },
    refreshColumns() {
      if (!this.gridApi) return;
      this.gridApi.setGridOption("columnDefs", this.buildColumnDefs());
    },
    refreshRows() {
      if (!this.gridApi) return;
      this.gridApi.setGridOption("rowData", this.rows);
    },
    clearFilters() {
      this.quickFilter = "";
      if (!this.gridApi) return;
      this.gridApi.setFilterModel(null);
    },
    exportFilteredCSV() {
      if (this.gridApi) this.gridApi.exportDataAsCsv({ onlySelected: false });
    },
  },
  template: `
      <div class="ag-table-wrap">
        <div class="ag-table-toolbar">
          <input
            v-model="quickFilter"
            class="ag-quick-filter"
            placeholder="Search visible table"
          >
          <button class="act-btn" @click="clearFilters">Clear Filters</button>
          <button class="act-btn" @click="exportFilteredCSV">CSV</button>
        </div>
        <div v-if="!gridReady && !canUseAgGrid" class="err-box">
          AG Grid failed to load from CDN.
        </div>
        <div ref="grid" class="ag-theme-quartz-dark ag-ioc-grid"></div>
      </div>
    `,
});
