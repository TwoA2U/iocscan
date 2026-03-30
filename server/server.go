// server/server.go — HTTP server: Start(), route registration, and all HTTP handlers.
//
// Router: go-chi/chi v5 (replaces net/http.ServeMux).
// All handlers are plain http.HandlerFunc — no Chi-specific types used inside them.
//
// Routes:
//
//	GET  /                   → HTML single-page app (and all web/ static assets)
//	GET  /api/health         → health check
//	GET  /api/integrations   → integration manifests
//	POST /api/scan           → Legacy IP enrichment response
//	POST /api/scan/generic   → Generic IP ScanResult response
//	POST /api/scan/hash      → Legacy hash enrichment response
//	POST /api/scan/hash/generic → Generic hash ScanResult response
//	POST /api/scan/ioc       → Legacy mixed IOC enrichment response
//	POST /api/scan/ioc/generic → Generic mixed IOC ScanResult response
//	POST /api/cache/clear    → Cache management
//
// Rate limiting: per-IP token-bucket (5 req burst, 1 req/500ms) on scan endpoints.
// Context propagation: r.Context() threaded through to vendor calls so a browser
// disconnect cancels in-flight goroutines.
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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"database/sql"

	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/TwoA2U/iocscan/admin"
	"github.com/TwoA2U/iocscan/auth"
	"github.com/TwoA2U/iocscan/integrations"
	"github.com/TwoA2U/iocscan/utils"
	"golang.org/x/time/rate"
)

// maxRequestBody caps inbound scan request bodies at 1 MB.
const maxRequestBody = 1 << 20 // 1 MB

// ── Package-level state ───────────────────────────────────────────────────────

var (
	globalCfgFile string
	globalUI      fs.FS
	globalDB      *sql.DB
	globalEncKey  []byte
	globalSM      *scs.SessionManager
)

// Start initialises the HTTP server and blocks until it exits.
// db and encKey come from main.go after InitDB() and LoadOrCreateSecret().
func Start(port int, cfgFile string, ui fs.FS, db *sql.DB, encKey []byte) {
	globalCfgFile = cfgFile
	globalUI = ui
	globalDB = db
	globalEncKey = encKey
	globalSM = auth.NewSessionManager(db)

	r := chi.NewRouter()

	// ── Global middleware ─────────────────────────────────────────────────────
	// RealIP: trust X-Forwarded-For so rate limiting works behind a proxy.
	// Recoverer: catch panics and return 500 instead of crashing the process.
	// LoadAndSave: load and commit session data on every request.
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(globalSM.LoadAndSave)

	// ── Public routes — no auth required ─────────────────────────────────────
	r.Get("/api/health", serveHealth)
	r.Get("/api/integrations", serveIntegrations)

	// ── Auth routes — public ──────────────────────────────────────────────────
	r.Post("/auth/login", auth.ServeLogin(db, globalSM))
	r.Post("/auth/logout", auth.ServeLogout(globalSM))
	r.Get("/auth/me", auth.ServeMe(db, globalSM))
	// change-password is public so mustChangePw users can still reach it
	r.Post("/auth/change-password", auth.ServeChangePassword(db, globalSM))

	// ── Protected routes — RequireAuth ────────────────────────────────────────
	r.Group(func(r chi.Router) {
		r.Use(auth.RequireAuth(db, globalSM))

		// Scan endpoints
		r.Post("/api/scan", rateLimit(serveScan))
		r.Post("/api/scan/generic", rateLimit(serveGenericIPScan))
		r.Post("/api/scan/hash", rateLimit(serveHashScan))
		r.Post("/api/scan/hash/generic", rateLimit(serveGenericHashScan))
		r.Post("/api/scan/ioc", rateLimit(serveIOCScan))
		r.Post("/api/scan/ioc/generic", rateLimit(serveGenericIOCScan))
		r.Post("/api/cache/clear", serveCacheClear)

		// API key management
		r.Get("/api/keys", serveGetKeys)
		r.Put("/api/keys", serveSaveKeys)

		// Admin-only routes
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireAdmin)
			r.Get("/api/admin/users", admin.ServeListUsers(globalDB))
			r.Post("/api/admin/users", admin.ServeCreateUser(globalDB))
			r.Delete("/api/admin/users/{id}", admin.ServeDeleteUser(globalDB))
			r.Put("/api/admin/users/{id}/password", admin.ServeResetPassword(globalDB))
		})
	})

	// ── Static UI (catch-all — must be last) ─────────────────────────────────
	r.Handle("/*", http.HandlerFunc(serveUI))

	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("\U0001f310 iocscan web UI → http://localhost%s\n", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

// ── Per-IP rate limiting ──────────────────────────────────────────────────────

type ipLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen atomic.Int64
}

var (
	ipLimiters  sync.Map
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

// rateLimit is a plain http.HandlerFunc adapter — fully compatible with Chi.
func rateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		if !getLimiter(ip).Allow() {
			jsonError(w, "rate limit exceeded — please slow down", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// ── runChunked ────────────────────────────────────────────────────────────────

func runChunked(ctx context.Context, count, chunkSize int, delay time.Duration, fn func(i int)) {
	for start := 0; start < count; start += chunkSize {
		if ctx.Err() != nil {
			return
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

// ── Handlers ──────────────────────────────────────────────────────────────────
// All handlers are plain func(w http.ResponseWriter, r *http.Request).
// Method enforcement is handled by Chi at registration — no r.Method checks needed.

func serveHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok","service":"iocscan"}`))
}

func serveIntegrations(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=60")
	if err := json.NewEncoder(w).Encode(integrations.Manifests()); err != nil {
		jsonError(w, "failed to serialize integrations", http.StatusInternalServerError)
	}
}

func serveUI(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".html") {
		w.Header().Set("Cache-Control", "no-cache")
	}
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

func webDirs() []string {
	candidates := []string{"web"}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "web"))
	}
	return candidates
}

// loadKeys loads the authenticated user's decrypted API keys from the DB.
// Falls back to the config file for any key not set in the DB.
// This allows backward compatibility during the transition period.
func loadKeys(r *http.Request) *auth.APIKeys {
	user := auth.UserFromContext(r.Context())
	if user != nil {
		keys, err := auth.GetKeys(globalDB, user.ID, globalEncKey)
		if err == nil {
			// Fill any empty DB keys from config as a backward-compatible fallback.
			applyConfigFallback(keys)
			return keys
		}
	}
	// No session user (shouldn't happen since RequireAuth runs first) —
	// fall back to config file only.
	keys := &auth.APIKeys{}
	applyConfigFallback(keys)
	return keys
}

func applyConfigFallback(keys *auth.APIKeys) {
	if keys == nil {
		return
	}

	// Legacy fallback for existing installs still using ~/.iocscan.yaml.
	cfg, err := utils.GetAPI(globalCfgFile)
	if err != nil || legacyKeysEmpty(cfg) {
		// If a custom config path points at the new config format, also try
		// the legacy default path before giving up.
		if globalCfgFile != "" {
			cfg, err = utils.GetAPI("")
		}
		if err != nil || legacyKeysEmpty(cfg) {
			return
		}
	}
	if keys.VTKey == "" {
		keys.VTKey = cfg.VTAPI
	}
	if keys.AbuseKey == "" {
		keys.AbuseKey = cfg.AbuseAPI
	}
	if keys.IPApiKey == "" {
		keys.IPApiKey = cfg.IPapiAPI
	}
	if keys.AbuseCHKey == "" {
		keys.AbuseCHKey = cfg.AbuseCHAPI
	}
	if keys.GreyNoiseKey == "" {
		keys.GreyNoiseKey = cfg.GreyNoiseAPI
	}
}

func legacyKeysEmpty(cfg *utils.CollectionAPI) bool {
	if cfg == nil {
		return true
	}
	return cfg.VTAPI == "" &&
		cfg.AbuseAPI == "" &&
		cfg.IPapiAPI == "" &&
		cfg.AbuseCHAPI == "" &&
		cfg.GreyNoiseAPI == ""
}

// ── Scan request types ────────────────────────────────────────────────────────

type scanRequest struct {
	IP           string `json:"ip"`
	VTKey        string `json:"vt_key"`
	AbuseKey     string `json:"abuse_key"`
	IPApiKey     string `json:"ipapi_key"`
	AbuseCHKey   string `json:"abusech_key"`
	GreyNoiseKey string `json:"greynoise_key"`
	UseCache     bool   `json:"use_cache"`
}

type genericScanEntry struct {
	IOC    string            `json:"ioc"`
	Type   string            `json:"type"`
	Result *utils.ScanResult `json:"result,omitempty"`
	Error  string            `json:"error,omitempty"`
}

func genericScanResult(ctx context.Context, ioc string, iocType integrations.IOCType, keys *auth.APIKeys, useCache bool) (*utils.ScanResult, error) {
	keyMap := utils.BuildKeys(keys.VTKey, keys.AbuseKey, keys.IPApiKey, keys.AbuseCHKey)
	keyMap["greynoise"] = keys.GreyNoiseKey
	return utils.Scan(ctx, ioc, iocType, keyMap, useCache)
}

func serveGenericIPScan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	var req struct {
		IP       string `json:"ip"`
		UseCache bool   `json:"use_cache"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.IP == "" {
		jsonError(w, `"ip" field is required`, http.StatusBadRequest)
		return
	}

	ips, err := utils.CheckIP(req.IP)
	if err != nil {
		jsonError(w, fmt.Sprintf("invalid IP: %v", err), http.StatusBadRequest)
		return
	}

	keys := loadKeys(r)
	results := make([]genericScanEntry, len(ips))
	for i, ip := range ips {
		results[i] = genericScanEntry{IOC: ip, Type: string(utils.TypeIP)}
	}

	ctx := r.Context()
	runChunked(ctx, len(ips), 10, 300*time.Millisecond, func(i int) {
		sr, err := genericScanResult(ctx, ips[i], integrations.IOCTypeIP, keys, req.UseCache)
		if err != nil {
			results[i].Error = err.Error()
			return
		}
		results[i].Result = sr
	})

	writeJSON(w, results)
}

func serveScan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.IP == "" {
		jsonError(w, `"ip" field is required`, http.StatusBadRequest)
		return
	}

	keys := loadKeys(r)

	ips, err := utils.CheckIP(req.IP)
	if err != nil {
		jsonError(w, fmt.Sprintf("invalid IP: %v", err), http.StatusBadRequest)
		return
	}

	processor := utils.NewIPProcessor(keys.VTKey, keys.AbuseKey, keys.IPApiKey, keys.AbuseCHKey, keys.GreyNoiseKey)

	type entry struct {
		IP     string          `json:"ip"`
		Result json.RawMessage `json:"result,omitempty"`
		Error  string          `json:"error,omitempty"`
	}

	results := make([]entry, len(ips))
	for i, ip := range ips {
		results[i] = entry{IP: ip}
	}

	ctx := r.Context()
	runChunked(ctx, len(ips), 10, 300*time.Millisecond, func(i int) {
		raw, err := processor.Lookup(ctx, ips[i], req.UseCache)
		if err != nil {
			results[i].Error = err.Error()
			return
		}
		results[i].Result = json.RawMessage(raw)
	})

	writeJSON(w, results)
}

func serveGenericHashScan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	var req struct {
		Hashes   []string `json:"hashes"`
		UseCache bool     `json:"use_cache"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if len(req.Hashes) == 0 {
		jsonError(w, `"hashes" field is required`, http.StatusBadRequest)
		return
	}
	if len(req.Hashes) > 100 {
		req.Hashes = req.Hashes[:100]
	}

	keys := loadKeys(r)
	results := make([]genericScanEntry, len(req.Hashes))
	for i, hash := range req.Hashes {
		h := strings.ToLower(strings.TrimSpace(hash))
		results[i] = genericScanEntry{IOC: h, Type: string(utils.TypeHash)}
		if utils.DetectIOCType(h) != utils.TypeHash {
			results[i].Error = "unsupported hash (expected MD5/SHA1/SHA256 hex)"
		}
	}

	ctx := r.Context()
	runChunked(ctx, len(req.Hashes), 5, 500*time.Millisecond, func(i int) {
		if results[i].Error != "" {
			return
		}
		sr, err := genericScanResult(ctx, results[i].IOC, integrations.IOCTypeHash, keys, req.UseCache)
		if err != nil {
			results[i].Error = err.Error()
			return
		}
		results[i].Result = sr
	})

	writeJSON(w, results)
}

func serveHashScan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	var req struct {
		Hashes     []string `json:"hashes"`
		VTKey      string   `json:"vt_key"`
		AbuseCHKey string   `json:"abusech_key"`
		UseCache   bool     `json:"use_cache"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if len(req.Hashes) == 0 {
		jsonError(w, `"hashes" field is required`, http.StatusBadRequest)
		return
	}
	if len(req.Hashes) > 100 {
		req.Hashes = req.Hashes[:100]
	}

	keys := loadKeys(r)

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
	runChunked(ctx, len(req.Hashes), 5, 500*time.Millisecond, func(i int) {
		raw, err := utils.LookupHash(ctx, req.Hashes[i], keys.VTKey, keys.AbuseCHKey, req.UseCache)
		if err != nil {
			results[i].Error = err.Error()
			return
		}
		results[i].Result = json.RawMessage(raw)
	})

	writeJSON(w, results)
}

func serveGenericIOCScan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	var req struct {
		IOCs     []string `json:"iocs"`
		UseCache bool     `json:"use_cache"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if len(req.IOCs) == 0 {
		jsonError(w, `"iocs" field is required`, http.StatusBadRequest)
		return
	}
	if len(req.IOCs) > 100 {
		req.IOCs = req.IOCs[:100]
	}

	keys := loadKeys(r)
	results := make([]genericScanEntry, len(req.IOCs))
	for i, ioc := range req.IOCs {
		ioc = strings.TrimSpace(ioc)
		results[i] = genericScanEntry{
			IOC:  ioc,
			Type: string(utils.DetectIOCType(ioc)),
		}
		if results[i].Type == string(utils.TypeUnknown) {
			results[i].Error = "unknown IOC type"
		}
	}

	ctx := r.Context()
	var pipelineWg sync.WaitGroup
	pipelineWg.Add(3)

	runGenericBatch := func(idxs []int, chunkSize int, delay time.Duration, iocType integrations.IOCType) {
		defer pipelineWg.Done()
		runChunked(ctx, len(idxs), chunkSize, delay, func(i int) {
			idx := idxs[i]
			sr, err := genericScanResult(ctx, results[idx].IOC, iocType, keys, req.UseCache)
			if err != nil {
				results[idx].Error = err.Error()
				return
			}
			results[idx].Result = sr
		})
	}

	var ipIdxs, hashIdxs, domainIdxs []int
	for i, entry := range results {
		switch entry.Type {
		case string(utils.TypeIP):
			ipIdxs = append(ipIdxs, i)
		case string(utils.TypeHash):
			hashIdxs = append(hashIdxs, i)
		case string(utils.TypeDomain):
			domainIdxs = append(domainIdxs, i)
		}
	}

	go runGenericBatch(ipIdxs, 10, 300*time.Millisecond, integrations.IOCTypeIP)
	go runGenericBatch(hashIdxs, 5, 500*time.Millisecond, integrations.IOCTypeHash)
	go runGenericBatch(domainIdxs, 5, 500*time.Millisecond, integrations.IOCTypeDomain)

	pipelineWg.Wait()
	writeJSON(w, results)
}

func serveIOCScan(w http.ResponseWriter, r *http.Request) {
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
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if len(req.IOCs) == 0 {
		jsonError(w, `"iocs" field is required`, http.StatusBadRequest)
		return
	}
	if len(req.IOCs) > 100 {
		req.IOCs = req.IOCs[:100]
	}

	keys := loadKeys(r)

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
	processor := utils.NewIPProcessor(keys.VTKey, keys.AbuseKey, keys.IPApiKey, keys.AbuseCHKey, keys.GreyNoiseKey)

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

	var pipelineWg sync.WaitGroup
	pipelineWg.Add(3)

	go func() {
		defer pipelineWg.Done()
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
		runChunked(ctx, len(hashIdxs), 5, 500*time.Millisecond, func(i int) {
			idx := hashIdxs[i]
			raw, err := utils.LookupHash(ctx, results[idx].IOC, keys.VTKey, keys.AbuseCHKey, req.UseCache)
			if err != nil {
				results[idx].Error = err.Error()
				return
			}
			results[idx].Result = json.RawMessage(raw)
		})
	}()

	go func() {
		defer pipelineWg.Done()
		runChunked(ctx, len(domainIdxs), 5, 500*time.Millisecond, func(i int) {
			idx := domainIdxs[i]
			raw, err := utils.LookupDomain(ctx, results[idx].IOC, keys.VTKey, keys.AbuseCHKey, req.UseCache)
			if err != nil {
				results[idx].Error = err.Error()
				return
			}
			results[idx].Result = json.RawMessage(raw)
		})
	}()

	pipelineWg.Wait()
	writeJSON(w, results)
}

func serveCacheClear(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Table string `json:"table"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	tables := integrations.CacheTables()
	if req.Table != "" && req.Table != "all" {
		tables = []string{req.Table}
	}

	cleared := utils.ClearCaches(tables)
	writeJSON(w, map[string]any{
		"cleared": cleared,
		"tables":  tables,
	})
}

// serveGetKeys handles GET /api/keys.
// Returns masked key display values — never exposes plaintext.
func serveGetKeys(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	keys, err := auth.GetKeys(globalDB, user.ID, globalEncKey)
	if err != nil {
		jsonError(w, "failed to load keys", http.StatusInternalServerError)
		return
	}

	writeJSON(w, keys.ToMasked())
}

// serveSaveKeys handles PUT /api/keys.
// Empty string fields are ignored — only non-empty values are updated.
func serveSaveKeys(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req auth.SaveKeysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := auth.SaveKeys(globalDB, user.ID, globalEncKey, req); err != nil {
		jsonError(w, "failed to save keys", http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]bool{"ok": true})
}

// ── Response helpers ──────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, v any) {
	out, err := json.Marshal(v)
	if err != nil {
		jsonError(w, "failed to serialize response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

func jsonError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q}`, msg)
}
