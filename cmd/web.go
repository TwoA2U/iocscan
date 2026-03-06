// cmd/web.go — "web" subcommand: starts an HTTP server with the IOC scanner UI.
//
// Routes:
//   GET  /                → HTML single-page app
//   POST /api/scan        → IP enrichment endpoint
//   POST /api/scan/hash   → Hash enrichment endpoint
//   POST /api/cache/clear → Cache management endpoint
//
// Usage:
//
//	iocscan web
//	iocscan web --port 9090
package cmd

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/TwoA2U/iocscan/utils"
	"github.com/spf13/cobra"
)

// embeddedFS holds the compiled-in web/ directory, set by main.go via SetEmbeddedUI.
var embeddedFS fs.FS

// SetEmbeddedUI is called from main.go to pass the //go:embed FS into this package.
func SetEmbeddedUI(f interface{ Open(string) (fs.File, error) }) {
	// Unwrap to the web/ sub-tree so paths are relative (e.g. "index.html" not "web/index.html").
	sub, err := fs.Sub(f.(fs.FS), "web")
	if err != nil {
		panic("embed: could not sub into web/: " + err.Error())
	}
	embeddedFS = sub
}

var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Start the web UI for IOC scanning",
	Example: `  iocscan web
  iocscan web --port 9090`,
	RunE: func(cmd *cobra.Command, args []string) error {
		port, _ := cmd.Flags().GetInt("port")
		addr := fmt.Sprintf(":%d", port)

		// API routes registered first so the catch-all "/" doesn't swallow them.
		http.HandleFunc("/api/scan", serveScan)
		http.HandleFunc("/api/scan/hash", serveHashScan)
		http.HandleFunc("/api/cache/clear", serveCacheClear)
		// Static file handler: serves JS modules (main.js, composables/, components/)
		// with correct MIME types. Falls back to embedded binary in production.
		http.HandleFunc("/", serveUI)

		fmt.Printf("🌐 iocscan web UI → http://localhost%s\n", addr)
		return http.ListenAndServe(addr, nil)
	},
}

// serveUI serves all static files under web/ (index.html, main.js, composables/, components/).
// Dev mode:    reads from the web/ directory on disk — edit files and refresh without rebuilding.
// Production:  serves from the embed.FS baked into the binary at compile time.
// http.FileServer handles MIME types automatically (.js → text/javascript, etc.)
func serveUI(w http.ResponseWriter, r *http.Request) {
	// Dev mode: web/ directory exists on disk next to the binary.
	if _, err := os.Stat("web"); err == nil {
		http.FileServer(http.Dir("web")).ServeHTTP(w, r)
		return
	}
	// Production: serve from the embedded FS.
	http.FileServer(http.FS(embeddedFS)).ServeHTTP(w, r)
}

// scanRequest is the JSON body accepted by POST /api/scan.
type scanRequest struct {
	IP         string `json:"ip"`
	Mode       string `json:"mode"` // "simple" or "complex" (default: "complex")
	VTKey      string `json:"vt_key"`
	AbuseKey   string `json:"abuse_key"`
	IPApiKey   string `json:"ipapi_key"`
	AbuseCHKey string `json:"abusech_key"` // Single key for MalwareBazaar + ThreatFox
	UseCache   bool   `json:"use_cache"`
}

// serveScan runs IP enrichment for every IP in the request and returns a JSON array.
func serveScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.IP == "" {
		http.Error(w, `"ip" field is required`, http.StatusBadRequest)
		return
	}
	if req.Mode == "" {
		req.Mode = "complex"
	}

	// Fall back to saved config if keys were not provided in the request body.
	if cfg, err := utils.GetAPI(cfgFile); err == nil {
		if req.VTKey == "" {
			req.VTKey = cfg.VTAPI
		}
		if req.AbuseKey == "" {
			req.AbuseKey = cfg.AbuseAPI
		}
		if req.IPApiKey == "" {
			req.IPApiKey = cfg.IPapiAPI
		}
		if req.AbuseCHKey == "" {
			req.AbuseCHKey = cfg.AbuseCHAPI
		}
	}

	ips, err := utils.CheckIP(req.IP)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid IP: %v", err), http.StatusBadRequest)
		return
	}

	processor := utils.NewIPProcessor(req.VTKey, req.AbuseKey, req.IPApiKey, req.AbuseCHKey)

	type entry struct {
		IP     string          `json:"ip"`
		Result json.RawMessage `json:"result,omitempty"`
		Error  string          `json:"error,omitempty"`
	}

	results := make([]entry, len(ips))
	for i, ip := range ips {
		results[i] = entry{IP: ip}
	}

	// Process in chunks of 10 concurrently, with a small pause between chunks
	// to avoid hammering rate-limited APIs on bulk scans.
	const chunkSize = 10
	for start := 0; start < len(ips); start += chunkSize {
		end := start + chunkSize
		if end > len(ips) {
			end = len(ips)
		}
		chunk := ips[start:end]

		var wg sync.WaitGroup
		for i, ip := range chunk {
			wg.Add(1)
			go func(idx int, ipAddr string) {
				defer wg.Done()
				raw, err := processor.Lookup(ipAddr, req.Mode, req.UseCache)
				if err != nil {
					results[start+idx].Error = err.Error()
					return
				}
				results[start+idx].Result = json.RawMessage(raw)
			}(i, ip)
		}
		wg.Wait()

		if end < len(ips) {
			time.Sleep(300 * time.Millisecond)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// serveHashScan handles POST /api/scan/hash — enriches a list of hashes.
func serveHashScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Hashes     []string `json:"hashes"`
		VTKey      string   `json:"vt_key"`
		AbuseCHKey string   `json:"abusech_key"` // Single key for MalwareBazaar + ThreatFox
		UseCache   bool     `json:"use_cache"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if len(req.Hashes) == 0 {
		http.Error(w, `"hashes" field is required`, http.StatusBadRequest)
		return
	}
	if len(req.Hashes) > 100 {
		req.Hashes = req.Hashes[:100]
	}

	// Fall back to saved config
	if cfg, err := utils.GetAPI(cfgFile); err == nil {
		if req.VTKey == "" {
			req.VTKey = cfg.VTAPI
		}
		if req.AbuseCHKey == "" {
			req.AbuseCHKey = cfg.AbuseCHAPI
		}
	}

	type entry struct {
		Hash   string          `json:"hash"`
		Result json.RawMessage `json:"result,omitempty"`
		Error  string          `json:"error,omitempty"`
	}

	results := make([]entry, len(req.Hashes))
	for i, h := range req.Hashes {
		results[i] = entry{Hash: h}
	}

	const chunkSize = 5 // VT free tier: 4 req/min — keep conservative
	for start := 0; start < len(req.Hashes); start += chunkSize {
		end := start + chunkSize
		if end > len(req.Hashes) {
			end = len(req.Hashes)
		}

		var wg sync.WaitGroup
		for i, h := range req.Hashes[start:end] {
			wg.Add(1)
			go func(idx int, hash string) {
				defer wg.Done()
				raw, err := utils.LookupHash(hash, req.VTKey, req.AbuseCHKey, req.UseCache)
				if err != nil {
					results[start+idx].Error = err.Error()
					return
				}
				results[start+idx].Result = json.RawMessage(raw)
			}(i, h)
		}
		wg.Wait()

		if end < len(req.Hashes) {
			time.Sleep(500 * time.Millisecond)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// serveCacheClear handles POST /api/cache/clear — wipes a specific cache table or all caches.
func serveCacheClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Table string `json:"table"` // "VT_HASH", "MB_HASH", "TF_HASH", "TF_IP", or "all"
	}
	json.NewDecoder(r.Body).Decode(&req)

	tables := []string{"VT_HASH", "MB_HASH", "TF_HASH", "TF_IP"}
	if req.Table != "" && req.Table != "all" {
		tables = []string{req.Table}
	}

	cleared := utils.ClearHashCaches(tables)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"cleared": cleared,
		"tables":  tables,
	})
}

func init() {
	webCmd.Flags().IntP("port", "p", 8080, "Port to listen on")
	rootCmd.AddCommand(webCmd)
}
