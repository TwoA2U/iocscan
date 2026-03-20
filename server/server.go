// server/server.go — HTTP server: Start(), route registration, and all HTTP handlers.
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
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"path/filepath"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TwoA2U/iocscan/integrations"
	"github.com/TwoA2U/iocscan/utils"
	"golang.org/x/time/rate"
)

// maxRequestBody caps inbound scan request bodies at 1 MB.
// Prevents unbounded memory allocation from oversized POST bodies
// before JSON decoding starts.
const maxRequestBody = 1 << 20 // 1 MB

// ── Package-level state ───────────────────────────────────────────────────────

var (
	globalCfgFile string
	globalUI      fs.FS
)

// Start initialises the HTTP server and blocks until it exits.
// ui is the embedded web/ filesystem. port is the TCP port to listen on.
// cfgFile is the optional config file path (empty = use default).
func Start(port int, cfgFile string, ui fs.FS) {
	globalCfgFile = cfgFile
	globalUI = ui

	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", serveHealth)
	mux.HandleFunc("/api/integrations", serveIntegrations)
	mux.HandleFunc("/api/scan", rateLimit(serveScan))
	mux.HandleFunc("/api/scan/hash", rateLimit(serveHashScan))
	mux.HandleFunc("/api/scan/ioc", rateLimit(serveIOCScan))
	mux.HandleFunc("/api/cache/clear", serveCacheClear)
	mux.HandleFunc("/", serveUI)

	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("🌐 iocscan web UI → http://localhost%s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

// ── Per-IP rate limiting ──────────────────────────────────────────────────────
//
// Each remote IP gets its own token-bucket limiter (5 req burst, 1 req/500ms).
// A background goroutine prunes entries idle for more than 5 minutes so the
// map doesn't grow unbounded on a busy server.

type ipLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen atomic.Int64 // unix nanoseconds; updated on every request
}

var (
	ipLimiters  sync.Map // map[string]*ipLimiterEntry
	limiterOnce sync.Once
)

func getLimiter(ip string) *rate.Limiter {
	limiterOnce.Do(func() {
		go func() {
			for range time.Tick(5 * time.Minute) {
				cutoff := time.Now().Add(-5 * time.Minute).UnixNano()
				ipLimiters.Range(func(k, v any) bool {
					if v.(*ipLimiterEntry).lastSeen.Load() < cutoff {
						ipLimiters.Delete(k)
					}
					return true
				})
			}
		}()
	})

	e := &ipLimiterEntry{
		limiter: rate.NewLimiter(rate.Every(500*time.Millisecond), 5),
	}
	e.lastSeen.Store(time.Now().UnixNano())
	v, _ := ipLimiters.LoadOrStore(ip, e)
	entry := v.(*ipLimiterEntry)
	entry.lastSeen.Store(time.Now().UnixNano())
	return entry.limiter
}

// rateLimit is a thin middleware wrapper that enforces per-IP rate limiting.
// Returns HTTP 429 when the caller's token bucket is empty.
func rateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr // fallback: use raw value if no port present
		}
		if !getLimiter(ip).Allow() {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"rate limit exceeded — please slow down"}`, http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// ── runChunked ────────────────────────────────────────────────────────────────
//
// runChunked fans out fn(i) for each index in [0, count) in batches of
// chunkSize, waiting for each batch to finish before starting the next.
// Between batches it sleeps for delay (unless ctx is already cancelled).
// fn receives the absolute index into the full slice so callers can write
// directly into a pre-allocated results slice without synchronisation.
func runChunked(ctx context.Context, count, chunkSize int, delay time.Duration, fn func(i int)) {
	for start := 0; start < count; start += chunkSize {
		if ctx.Err() != nil {
			return // client disconnected — stop early
		}
		end := start + chunkSize
		if end > count {
			end = count
		}
		var wg sync.WaitGroup
		for i := start; i < end; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				fn(idx)
			}(i)
		}
		wg.Wait()
		if end < count {
			select {
			case <-ctx.Done():
			case <-time.After(delay):
			}
		}
	}
}

// serveHealth handles GET /api/health — returns a minimal JSON payload that
// load balancers and monitoring tools can poll to confirm the server is up.
func serveHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok","service":"iocscan"}`))
}

// serveIntegrations handles GET /api/integrations.
// Returns the full Manifest slice for every registered integration as JSON.
// The Vue frontend fetches this once at boot time (useIntegrations.js) and
// uses it to render cards, table columns, settings inputs, and risk colors
// without any hardcoded vendor names in JavaScript.
func serveIntegrations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// Cache for 60 seconds — manifests are static after startup so the
	// browser doesn't need to refetch on every page load, but a short TTL
	// means a server restart is reflected quickly.
	w.Header().Set("Cache-Control", "public, max-age=60")
	if err := json.NewEncoder(w).Encode(integrations.Manifests()); err != nil {
		http.Error(w, `{"error":"failed to serialize integrations"}`, http.StatusInternalServerError)
	}
}

// serveUI serves the full web/ directory tree (index.html + JS modules + assets).
// Dev mode:    serves directly from disk when a web/ directory exists (hot-reload).
// Production:  falls back to the embedded FS baked into the binary by main.go.
func serveUI(w http.ResponseWriter, r *http.Request) {
	// Disable browser caching for JS and HTML so that updated files on disk
	// are always fetched — prevents the "stale ES module" class of bugs.
	p := r.URL.Path
	if strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".html") {
		w.Header().Set("Cache-Control", "no-cache")
	}

	// Check CWD first, then the directory the binary lives in, then fall back
	// to the embedded FS.  This means the binary can be run from any directory
	// and will still pick up a live web/ tree sitting next to the executable.
	for _, dir := range webDirs() {
		if _, err := os.Stat(dir); err == nil {
			http.FileServer(http.Dir(dir)).ServeHTTP(w, r)
			return
		}
	}
	if globalUI != nil {
		http.FileServer(http.FS(globalUI)).ServeHTTP(w, r)
		return
	}
	http.Error(w, "UI not available", http.StatusNotFound)
}

// webDirs returns candidate paths for the web/ directory in preference order:
// 1. web/  relative to the current working directory (original behaviour)
// 2. web/  sitting next to the running executable
func webDirs() []string {
	candidates := []string{"web"}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "web"))
	}
	return candidates
}

// scanRequest is the JSON body accepted by POST /api/scan.
type scanRequest struct {
	IP           string `json:"ip"`
	VTKey        string `json:"vt_key"`
	AbuseKey     string `json:"abuse_key"`
	IPApiKey     string `json:"ipapi_key"`
	AbuseCHKey   string `json:"abusech_key"`
	GreyNoiseKey string `json:"greynoise_key"`
	UseCache     bool   `json:"use_cache"`
}

// serveScan runs IP enrichment for every IP in the request and returns a JSON array.
func serveScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.IP == "" {
		http.Error(w, `"ip" field is required`, http.StatusBadRequest)
		return
	}

	ips, err := utils.CheckIP(req.IP)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid IP: %v", err), http.StatusBadRequest)
		return
	}

	processor := utils.NewIPProcessor(req.VTKey, req.AbuseKey, req.IPApiKey, req.AbuseCHKey, req.GreyNoiseKey)

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
	runChunked(ctx, len(ips), 10, 300*time.Millisecond, func(i int) {
		raw, err := processor.Lookup(ctx, ips[i], req.UseCache)
		if err != nil {
			results[i].Error = err.Error()
			return
		}
		results[i].Result = json.RawMessage(raw)
	})

	out, err := json.Marshal(results)
	if err != nil {
		http.Error(w, `{"error":"failed to serialize response"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

// serveHashScan handles POST /api/scan/hash — enriches a list of file hashes.
func serveHashScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
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

	// VT free tier: 4 req/min — keep chunk size conservative
	runChunked(ctx, len(req.Hashes), 5, 500*time.Millisecond, func(i int) {
		raw, err := utils.LookupHash(ctx, req.Hashes[i], req.VTKey, req.AbuseCHKey, req.UseCache)
		if err != nil {
			results[i].Error = err.Error()
			return
		}
		results[i].Result = json.RawMessage(raw)
	})

	out, err := json.Marshal(results)
	if err != nil {
		http.Error(w, `{"error":"failed to serialize response"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

// serveIOCScan handles POST /api/scan/ioc — accepts a mixed list of IOCs,
// auto-detects each type via DetectIOCType, and routes each to the correct
// enrichment path. IPs and hashes are processed concurrently within their
// respective pipelines.
//
// Request body:
//
//	{ "iocs": ["1.2.3.4", "abc123...", "evil.com"], "use_cache": true,
//	  "vt_key": "...", "abuse_key": "...", "ipapi_key": "...", "abusech_key": "..." }
//
// Response:
//
//	[ { "ioc": "1.2.3.4", "type": "ip",   "result": {...} },
//	  { "ioc": "abc123",  "type": "hash",  "result": {...} },
//	  { "ioc": "evil.com","type": "domain","error": "domain scanning not yet supported" } ]
func serveIOCScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req struct {
		IOCs         []string `json:"iocs"`
		VTKey        string   `json:"vt_key"`
		AbuseKey     string   `json:"abuse_key"`
		IPApiKey     string   `json:"ipapi_key"`
		AbuseCHKey   string   `json:"abusech_key"`
		GreyNoiseKey string   `json:"greynoise_key"`
		UseCache     bool     `json:"use_cache"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if len(req.IOCs) == 0 {
		http.Error(w, `"iocs" field is required`, http.StatusBadRequest)
		return
	}
	if len(req.IOCs) > 100 {
		req.IOCs = req.IOCs[:100]
	}

	type iocEntry struct {
		IOC    string          `json:"ioc"`
		Type   string          `json:"type"`
		Result json.RawMessage `json:"result,omitempty"`
		Error  string          `json:"error,omitempty"`
	}

	results := make([]iocEntry, len(req.IOCs))
	for i, ioc := range req.IOCs {
		results[i] = iocEntry{IOC: ioc, Type: string(utils.DetectIOCType(ioc))}
	}

	ctx := r.Context()
	processor := utils.NewIPProcessor(req.VTKey, req.AbuseKey, req.IPApiKey, req.AbuseCHKey, req.GreyNoiseKey)

	// Partition indices by IOC type — each pipeline owns disjoint index slices,
	// so concurrent writes to results[] are race-free.
	var ipIdxs, hashIdxs, domainIdxs []int
	for i, e := range results {
		switch e.Type {
		case string(utils.TypeIP):
			ipIdxs = append(ipIdxs, i)
		case string(utils.TypeHash):
			hashIdxs = append(hashIdxs, i)
		case string(utils.TypeDomain):
			domainIdxs = append(domainIdxs, i)
		default:
			results[i].Error = fmt.Sprintf("%s scanning not yet supported", e.Type)
		}
	}

	// Fan-out all three pipelines concurrently.
	var pipelineWg sync.WaitGroup
	pipelineWg.Add(3)

	go func() {
		defer pipelineWg.Done()
		// IPs: chunk 10, 300ms inter-chunk delay.
		runChunked(ctx, len(ipIdxs), 10, 300*time.Millisecond, func(i int) {
			idx := ipIdxs[i]
			raw, err := processor.Lookup(ctx, results[idx].IOC, req.UseCache)
			if err != nil {
				results[idx].Error = err.Error()
				return
			}
			results[idx].Result = json.RawMessage(raw)
		})
	}()

	go func() {
		defer pipelineWg.Done()
		// Hashes: chunk 5, 500ms inter-chunk delay for VT rate limit.
		runChunked(ctx, len(hashIdxs), 5, 500*time.Millisecond, func(i int) {
			idx := hashIdxs[i]
			raw, err := utils.LookupHash(ctx, results[idx].IOC, req.VTKey, req.AbuseCHKey, req.UseCache)
			if err != nil {
				results[idx].Error = err.Error()
				return
			}
			results[idx].Result = json.RawMessage(raw)
		})
	}()

	go func() {
		defer pipelineWg.Done()
		// Domains: chunk 5, 500ms inter-chunk delay (VT domain shares VT quota).
		runChunked(ctx, len(domainIdxs), 5, 500*time.Millisecond, func(i int) {
			idx := domainIdxs[i]
			raw, err := utils.LookupDomain(ctx, results[idx].IOC, req.VTKey, req.AbuseCHKey, req.UseCache)
			if err != nil {
				results[idx].Error = err.Error()
				return
			}
			results[idx].Result = json.RawMessage(raw)
		})
	}()

	pipelineWg.Wait()

	out, err := json.Marshal(results)
	if err != nil {
		http.Error(w, `{"error":"failed to serialize response"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
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
	payload := map[string]interface{}{
		"cleared": cleared,
		"tables":  tables,
	}
	out, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, `{"error":"failed to serialize response"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}
