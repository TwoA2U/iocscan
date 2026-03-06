// cmd/web.go — "web" subcommand: starts an HTTP server with the IOC scanner UI.
//
// Routes:
//   GET  /                → HTML single-page app (and all web/ static assets)
//   POST /api/scan        → IP enrichment endpoint
//   POST /api/scan/hash   → Hash enrichment endpoint
//   POST /api/cache/clear → Cache management endpoint
//
// Improvements in this revision:
//   1. Rate limiting — a token-bucket limiter (5 req/s burst, 2 req/s sustained)
//      guards both scan endpoints. Requests that exceed the limit receive HTTP 429
//      instead of triggering outbound vendor API calls that consume quota.
//   2. Context propagation — r.Context() is threaded through to Lookup /
//      LookupHash so a browser disconnect cancels in-flight vendor goroutines.
//   3. Dedicated ServeMux — no longer uses the default global mux, preventing
//      accidental route collisions with other packages.
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
	"golang.org/x/time/rate"
)

// embeddedFS holds the compiled-in web/ directory, set by main.go via SetEmbeddedUI.
var embeddedFS fs.FS

// SetEmbeddedUI is called from main.go to pass the embedded web/ FS into this package.
func SetEmbeddedUI(f fs.FS) {
	embeddedFS = f
}

// ── Rate limiter ──────────────────────────────────────────────────────────────
//
// scanLimiter caps how many scan requests the server accepts per second.
// Burst of 5 allows short interactive bursts; sustained rate of 2 req/s is
// generous for single-user use while preventing runaway scripted abuse.
var scanLimiter = rate.NewLimiter(rate.Every(500*time.Millisecond), 5)

// rateLimit is a thin middleware wrapper that returns HTTP 429 when the token
// bucket is empty.
func rateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !scanLimiter.Allow() {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"rate limit exceeded — please slow down"}`, http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Start the web UI for IOC scanning",
	Example: `  iocscan web
  iocscan web --port 9090`,
	RunE: func(cmd *cobra.Command, args []string) error {
		port, _ := cmd.Flags().GetInt("port")
		addr := fmt.Sprintf(":%d", port)

		// Use a dedicated mux so we don't pollute the global default mux.
		// API routes are registered before the catch-all UI handler so that
		// /api/* paths are never accidentally served the HTML app.
		mux := http.NewServeMux()
		mux.HandleFunc("/api/scan", rateLimit(serveScan))
		mux.HandleFunc("/api/scan/hash", rateLimit(serveHashScan))
		mux.HandleFunc("/api/cache/clear", serveCacheClear)
		mux.HandleFunc("/", serveUI)

		fmt.Printf("🌐 iocscan web UI → http://localhost%s\n", addr)
		return http.ListenAndServe(addr, mux)
	},
}

// serveUI serves the full web/ directory tree (index.html + JS modules + assets).
// Dev mode:    serves directly from disk when a web/ directory exists (hot-reload).
// Production:  falls back to the embedded FS baked into the binary by main.go.
func serveUI(w http.ResponseWriter, r *http.Request) {
	if _, err := os.Stat("web"); err == nil {
		http.FileServer(http.Dir("web")).ServeHTTP(w, r)
		return
	}
	if embeddedFS != nil {
		http.FileServer(http.FS(embeddedFS)).ServeHTTP(w, r)
		return
	}
	http.Error(w, "UI not available", http.StatusNotFound)
}

// scanRequest is the JSON body accepted by POST /api/scan.
type scanRequest struct {
	IP         string `json:"ip"`
	VTKey      string `json:"vt_key"`
	AbuseKey   string `json:"abuse_key"`
	IPApiKey   string `json:"ipapi_key"`
	AbuseCHKey string `json:"abusech_key"`
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

	// Fall back to saved config for any keys not supplied in the request body.
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

	// Thread the request context so a browser disconnect cancels in-flight
	// vendor goroutines instead of letting them run to completion.
	ctx := r.Context()

	// Process in chunks of 10 concurrently, with a small pause between chunks
	// to avoid hammering rate-limited APIs on bulk scans.
	const chunkSize = 10
	for start := 0; start < len(ips); start += chunkSize {
		if ctx.Err() != nil {
			break // client disconnected — stop early
		}
		end := start + chunkSize
		if end > len(ips) {
			end = len(ips)
		}

		var wg sync.WaitGroup
		for i, ip := range ips[start:end] {
			wg.Add(1)
			go func(idx int, ipAddr string) {
				defer wg.Done()
				raw, err := processor.Lookup(ctx, ipAddr, req.UseCache)
				if err != nil {
					results[start+idx].Error = err.Error()
					return
				}
				results[start+idx].Result = json.RawMessage(raw)
			}(i, ip)
		}
		wg.Wait()

		if end < len(ips) {
			select {
			case <-ctx.Done():
			case <-time.After(300 * time.Millisecond):
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// serveHashScan handles POST /api/scan/hash — enriches a list of file hashes.
func serveHashScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Hashes     []string `json:"hashes"`
		VTKey      string   `json:"vt_key"`
		AbuseCHKey string   `json:"abusech_key"`
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

	ctx := r.Context()

	const chunkSize = 5 // VT free tier: 4 req/min — keep conservative
	for start := 0; start < len(req.Hashes); start += chunkSize {
		if ctx.Err() != nil {
			break
		}
		end := start + chunkSize
		if end > len(req.Hashes) {
			end = len(req.Hashes)
		}

		var wg sync.WaitGroup
		for i, h := range req.Hashes[start:end] {
			wg.Add(1)
			go func(idx int, hash string) {
				defer wg.Done()
				raw, err := utils.LookupHash(ctx, hash, req.VTKey, req.AbuseCHKey, req.UseCache)
				if err != nil {
					results[start+idx].Error = err.Error()
					return
				}
				results[start+idx].Result = json.RawMessage(raw)
			}(i, h)
		}
		wg.Wait()

		if end < len(req.Hashes) {
			select {
			case <-ctx.Done():
			case <-time.After(500 * time.Millisecond):
			}
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
		Table string `json:"table"` // specific table name, or "all"
	}
	json.NewDecoder(r.Body).Decode(&req)

	tables := []string{"VT_IP", "ABUSE_IP", "IPAPIIS_IP", "VT_HASH", "MB_HASH", "TF_IP", "TF_HASH"}
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
