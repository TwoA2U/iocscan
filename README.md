# iocscan

[![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/TwoA2U/iocscan)](https://github.com/TwoA2U/iocscan/releases/latest)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macOS%20%7C%20windows-lightgrey)](#supported-platforms)

**Fast, multi-source threat intelligence enrichment for IPs, file hashes, and domains.**

Query indicators against VirusTotal, AbuseIPDB, ThreatFox, ipapi.is, MalwareBazaar, and GreyNoise — from a local web UI. Ships as a single self-contained binary with no runtime dependencies.

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Web UI](#web-ui)
- [API Reference](#api-reference)
- [Output Format](#output-format)
- [Risk Scoring](#risk-scoring)
- [Data Sources](#data-sources)
- [Supported Platforms](#supported-platforms)
- [Project Structure](#project-structure)
- [Adding a New Integration](#adding-a-new-integration)
- [Known Limitations](#known-limitations)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **IP enrichment** — geo, ASN, usage type, abuse score, VirusTotal verdicts, ThreatFox C2 intel, and GreyNoise internet-scanner classification. AbuseIPDB fields include confidence score, report count, distinct reporters, usage type, domain, Tor exit node flag, public/whitelisted status, hostnames, and deduplicated report categories mapped to human-readable names
- **Hash enrichment** — VirusTotal detections (with last scanned timestamp), MalwareBazaar metadata, code signing validation, Sigma rule hits, sandbox classifications
- **Domain enrichment** — VirusTotal multi-engine verdict, reputation, registrar, creation date, A records, categories, and ThreatFox C2 intelligence
- **Multi-signal risk scoring** — `riskLevel` computed from manifest-driven rules across all integrations; any single signal can escalate the level independently
- **Plugin architecture** — each integration is a self-contained Go file implementing a single interface; adding a new vendor requires one file and one registry line
- **Web UI** — Tailwind CSS + Vue 3, cards/table views, column visibility toggles, export to CSV/JSON, scan history. Cards show full vendor data including AbuseIPDB categories, VirusTotal last scanned time, and GreyNoise classification. Cards with API errors are hidden automatically — error detail remains in the raw JSON panel
- **Bulk scanning** — up to 100 IPs, hashes, or domains per request
- **Local cache** — SQLite-backed caching per integration to avoid redundant API calls
- **Rate limiting** — built-in token-bucket limiter with 1 MB request body cap
- **Single binary** — web UI is embedded at compile time, no external files needed
- **Minimal dependencies** — 3 external Go dependencies total (yaml.v3, x/time/rate, sqlite)

---

## How It Works

```
  Input (IP, Hash, or Domain)
            |
            v
      +-----------+
      |  iocscan  |  Web UI
      +-----+-----+
            |  registry.ForIOCType() -> enabled integrations for this IOC type
    +-------+------------------------------------------+
    |       |          |           |                   |
    v       v          v           v                   v
 ipapi.is  AbuseIPDB  VirusTotal  ThreatFox       GreyNoise
 geo/ASN   abuse      multi-engine C2/botnet      internet
 VPN/DC    score      verdicts     IOC intel       scanner
    |       |          |           |                   |
    +-------+------------------------------------------+
            |  orchestrator collects Results + Errors
            |  evaluateOverallRisk() reads manifest RiskRules
            v
      JSON result (Web UI)
            |
            v
      SQLite cache (per-integration table, auto-created)
```

All integrations are queried concurrently per indicator. Risk scoring is driven by declarative rules in each integration's manifest. Cache tables are created automatically from integration manifests at startup.

---

## Installation

### Download a release

Grab the latest pre-built binary for your platform from [Releases](https://github.com/TwoA2U/iocscan/releases/latest).

| Platform | File |
|----------|------|
| Linux x64 | `iocscan_linux_amd64.zip` |
| Linux ARM64 | `iocscan_linux_arm64.zip` |
| macOS x64 | `iocscan_darwin_amd64.zip` |
| macOS Apple Silicon | `iocscan_darwin_arm64.zip` |
| Windows x64 | `iocscan_windows_amd64.zip` |

Verify the download against `checksums.txt` included in each release.

### Build from source

Requires Go 1.22+.

```bash
git clone https://github.com/TwoA2U/iocscan.git
cd iocscan
go mod tidy
go build -o iocscan .
```

---

## Quick Start

### 1. Start the server

```bash
iocscan              # starts web UI on http://localhost:8080
iocscan -p 9090      # custom port
iocscan --help       # show usage
```

### 2. Enter your API keys

Open your browser. The API Keys panel at the top accepts keys for each vendor. Keys are sent per-scan request.

| Vendor | Key source | Required |
|--------|-----------|----------|
| VirusTotal | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) | Yes (IP + hash + domain) |
| AbuseIPDB | [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) | Yes (IP scans) |
| ipapi.is | [ipapi.is/developers.html](https://ipapi.is/developers.html) | No — free tier works without |
| abuse.ch | [bazaar.abuse.ch/api](https://bazaar.abuse.ch/api/) | No — MalwareBazaar + ThreatFox |
| GreyNoise | [viz.greynoise.io/signup](https://viz.greynoise.io/signup) | No — 10 lookups/day without |

Keys are entered in the API Keys panel in the web UI. They are sent per-scan and never stored on disk.

### 3. Config file (optional)

Create `~/.iocscan/config.yaml` to set a default port or database path:

```yaml
server:
  port: 8080

database:
  path: ""   # default: ~/.iocscan/iocscan.db
```

The `-p` flag always overrides the config file port.

---

## Web UI

**IP mode** — ipapi.is (geo/ASN) + AbuseIPDB (full report data, categories) + VirusTotal + ThreatFox + GreyNoise.
**Hash mode** — VirusTotal (with last scanned timestamp) + MalwareBazaar + ThreatFox.
**Domain mode** — VirusTotal (verdict, registrar, A records, categories) + ThreatFox.

| Feature | Description |
|---------|-------------|
| Cards view | Per-indicator detail cards with risk badges and source links. Cards with errors are hidden — data still visible in raw JSON panel |
| Table view | Sortable multi-indicator comparison table |
| Column toggles | Show/hide individual fields per section |
| Bulk input | Paste multiple indicators or upload a `.txt` / `.csv` file |
| Export | Download results as CSV or JSON |
| Copy | Copy to clipboard as JSON, CSV, or raw indicators only |
| Scan history | Last 20 scans with one-click re-scan |
| Cache toggle | Per-scan control over SQLite result caching |

---

## API Reference

All API responses use `Content-Type: application/json`, including errors.

### `GET /api/health`

```json
{ "status": "ok", "service": "iocscan" }
```

### `GET /api/integrations`

Returns the full manifest for every registered integration. The frontend fetches this once at boot to drive card layouts, table columns, and risk thresholds.

### `POST /api/scan`

IP enrichment.

```json
{
  "ip": "1.2.3.4",
  "vt_key": "...", "abuse_key": "...", "ipapi_key": "...",
  "abusech_key": "...", "greynoise_key": "...",
  "use_cache": true
}
```

### `POST /api/scan/hash`

Hash enrichment. Accepts up to 100 hashes (MD5, SHA1, or SHA256).

```json
{
  "hashes": ["<hash1>", "<hash2>"],
  "vt_key": "...", "abusech_key": "...",
  "use_cache": true
}
```

### `POST /api/scan/ioc`

Mixed IOC enrichment. IPs, hashes, and domains are auto-detected and routed to the correct pipeline.

```json
{
  "iocs": ["1.2.3.4", "<sha256>", "evil.com"],
  "vt_key": "...", "abuse_key": "...", "abusech_key": "...", "greynoise_key": "...",
  "use_cache": true
}
```

### `POST /api/cache/clear`

```json
{ "table": "all" }
```

Current cache tables: `VT_IP`, `ABUSE_IP`, `IPAPIIS_IP`, `GN_IP`, `VT_HASH`, `MB_HASH`, `TF_IP`, `TF_HASH`, `VT_DOMAIN`, `TF_DOMAIN`.

### Error responses

```json
{ "error": "description of what went wrong" }
```

---

## Output Format

### IP enrichment

```json
{
  "ipAddress": "45.77.34.87",
  "riskLevel": "CRITICAL",
  "geo": { "isp": "Vultr", "country": "Singapore", "city": "Singapore", "timezone": "Asia/Singapore" },
  "virustotal": {
    "malicious": 5, "suspicious": 1, "reputation": -11,
    "lastAnalysisDate": "2026-03-20 06:41 UTC"
  },
  "abuseipdb": {
    "confidenceScore": 82, "totalReports": 14, "numDistinctUsers": 9,
    "lastReportedAt": "2026-03-19T14:22:00+00:00",
    "usageType": "Data Center/Web Hosting/Transit",
    "domain": "vultr.com", "isTor": false,
    "isPublic": true, "isWhitelisted": false,
    "hostnames": [],
    "categories": ["Port Scan", "Hacking", "Brute-Force", "SSH"]
  },
  "threatfox": { "queryStatus": "ok", "malware": "win.cobalt_strike", "confidenceLevel": 100 },
  "greynoise": { "classification": "malicious", "noise": true, "riot": false, "name": "unknown", "lastSeen": "2026-03-19" }
}
```

### Hash enrichment

```json
{
  "hash": "d55f983c...", "hashType": "SHA256", "riskLevel": "CRITICAL",
  "virustotal": { "malicious": 58, "suggestedThreatLabel": "trojan.sodinokibi/revil" },
  "malwarebazaar": { "queryStatus": "ok", "signature": "Sodinokibi", "fileName": "revil.exe" },
  "threatfox": { "queryStatus": "ok" }
}
```

### Domain enrichment

```json
{
  "domain": "evil.com", "riskLevel": "HIGH",
  "vtDomain": { "malicious": 8, "registrar": "NameCheap", "suggestedThreatLabel": "malware.generic" },
  "threatfox": { "queryStatus": "ok", "malware": "win.emotet", "confidenceLevel": 75 }
}
```

---

## Risk Scoring

`riskLevel` is computed from declarative `RiskRule` definitions in each integration's manifest. The highest severity across all integrations wins.

### IP scoring

| Level | AbuseIPDB | VT Malicious | GreyNoise | ThreatFox |
|-------|:---------:|:------------:|:---------:|:---------:|
| `CRITICAL` | >= 75 | >= 5 | — | — |
| `HIGH` | >= 40 | >= 2 | `malicious` | confirmed |
| `MEDIUM` | >= 10 | >= 1 | `suspicious` or `noise=true` | — |
| `LOW` | > 0 | — | — | — |
| `CLEAN` | 0 | 0 | `benign` | no results |

### Hash scoring

| Level | VT Malicious | MalwareBazaar | ThreatFox |
|-------|:-----------:|:-------------:|:---------:|
| `CRITICAL` | >= 15 | — | — |
| `HIGH` | >= 5 | confirmed | confirmed |
| `MEDIUM` | >= 1 | — | — |
| `CLEAN` | 0 | not found | no results |

### Domain scoring

| Level | VT Malicious | ThreatFox |
|-------|:-----------:|:---------:|
| `CRITICAL` | >= 5 | — |
| `HIGH` | >= 2 | confirmed |
| `MEDIUM` | >= 1 | — |
| `CLEAN` | 0 | no results |

---

## Data Sources

| Source | IOC Types | Free Tier |
|--------|-----------|----------|
| [ipapi.is](https://ipapi.is) | IP | 1,000 req/day without a key |
| [AbuseIPDB](https://www.abuseipdb.com) | IP | 1,000 req/day — verbose mode returns full report list with category IDs |
| [VirusTotal](https://www.virustotal.com) | IP, Hash, Domain | 4 req/min, 500 req/day |
| [MalwareBazaar](https://bazaar.abuse.ch) | Hash | No hard limit |
| [ThreatFox](https://threatfox.abuse.ch) | IP, Hash, Domain | No hard limit |
| [GreyNoise](https://greynoise.io) | IP | 10 lookups/day without a key |

---

## Supported Platforms

| OS | amd64 | arm64 |
|----|:-----:|:-----:|
| Linux | ✓ | ✓ |
| macOS | ✓ | ✓ |
| Windows | ✓ | ✓ |

Linux and Windows binaries are compressed with UPX. macOS binaries are left uncompressed to avoid Gatekeeper issues.

---

## Project Structure

```
iocscan/
├── main.go                        — entry point: -p flag, config load, server start
├── config/
│   └── config.go                  — load ~/.iocscan/config.yaml via gopkg.in/yaml.v3
├── server/
│   └── server.go                  — Start(), HTTP mux, all handlers, rate limiting
├── integrations/
│   ├── integration.go             — Integration interface, Manifest types, EvaluateRisk()
│   ├── registry.go                — All(), ForIOCType(), Manifests(), CacheTables()
│   ├── cache.go                   — RWMutex-protected cache bridge
│   ├── abuseipdb.go               — AbuseIPDB integration (IP)
│   ├── greynoise.go               — GreyNoise Community API integration (IP)
│   ├── ipapi.go                   — ipapi.is integration (IP)
│   ├── malwarebazaar.go           — MalwareBazaar integration (Hash)
│   ├── threatfox.go               — ThreatFox integrations (IP, Hash, Domain)
│   └── virustotal.go              — VirusTotal integrations (IP, Hash, Domain)
├── internal/
│   └── httpclient/http.go         — shared HTTP client with context support
├── utils/
│   ├── common.go                  — dynamic InitDB(), cache helpers
│   ├── orchestrator.go            — generic Scan() fan-out, ScanResult, BuildKeys()
│   ├── iputil.go                  — IP output types, IPProcessor, GNResult
│   ├── iputil_shim.go             — Lookup() -> Scan() -> ComplexResult
│   ├── hashutil.go                — hash output types and helpers
│   ├── hashutil_shim.go           — LookupHash() -> Scan() -> HashResult
│   ├── domainutil.go              — LookupDomain() -> Scan() -> DomainResult
│   └── iocutil.go                 — IOC type detection (IP, hash, domain)
└── web/
    ├── components/
    │   ├── ColumnDrawer.js        — column visibility drawer
    │   ├── IntegrationCard.js     — generic card renderer (driven by manifests)
    │   ├── IOCScanner.js          — main scanner (IP, Hash, Domain tabs)
    │   └── ResultsTable.js        — sortable results table
    ├── composables/
    │   ├── useColumnVisibility.js — column toggle state
    │   ├── useDomainResults.js    — domain scan state, table, export
    │   ├── useHashResults.js      — hash scan state, table, export
    │   ├── useIntegrations.js     — manifest fetch at boot
    │   ├── useIOCScan.js          — central scan orchestration
    │   ├── useIPResults.js        — IP scan state, table, export
    │   └── useScanHistory.js      — scan history management
    ├── index.html                 — main UI entry point
    ├── main.js                    — Vue app bootstrap + loadManifests()
    └── utils.js                   — shared helpers (highlightJSON, escapeHTML)
```

---

## Adding a New Integration

### Cost at a glance

| IOC Type | Backend | Frontend | Estimated time |
|----------|:-------:|:--------:|----------------|
| IP | 3 | 2 | ~2h |
| Hash | 3 | 1 | ~1h 30m |
| Domain | 2 | 1 | ~1h 15m |

**Backend files** (all integration types):

| File | Change |
|------|--------|
| `integrations/yourvendor.go` | New file — fetch function, `Manifest()`, `Run()` |
| `integrations/registry.go` | +1 line |
| `utils/iputil_shim.go` or `utils/hashutil_shim.go` | +~10 lines mapping block (IP and hash only) |

**Frontend files** (required for all integration types):

| File | Change |
|------|--------|
| `web/components/IOCScanner.js` | Add hardcoded card template for the new vendor |
| `web/composables/useIOCScan.js` | Add key to `keys` reactive object + scan request body (if vendor requires a key) |

**Additional wiring for IP integrations that require a key** (e.g. GreyNoise):

| File | Change |
|------|--------|
| `server/server.go` | Add `YourVendorKey` field to `scanRequest` struct, pass to `NewIPProcessor` |
| `utils/iputil.go` | Add `yourvendorKey` field to `IPProcessor`, update `NewIPProcessor` signature |
| `utils/iputil_shim.go` | Pass `keys["yourvendor"] = p.yourvendorKey` |

> **Note:** The frontend card template and key wiring are currently manual steps because the card rendering for IP scans is not yet fully manifest-driven. This will be eliminated when the shim layer is removed — at that point, new integrations will truly require only the 2 backend files.

### Step 1 — Create `integrations/yourvendor.go`

```go
package integrations

import (
    "context"
    "encoding/json"
    "fmt"
    "github.com/TwoA2U/iocscan/internal/httpclient"
)

type YourVendor struct{}

func (y YourVendor) Manifest() Manifest {
    return Manifest{
        Name: "yourvendor", Label: "Your Vendor", Icon: "🔧",
        Enabled: true, IOCTypes: []IOCType{IOCTypeIP},
        Auth:  AuthConfig{KeyRef: "yourvendor", Label: "Your Vendor", Optional: true},
        Cache: CacheConfig{Table: "YV_IP", TTLHours: 24},
        RiskRules: []RiskRule{
            {
                Field: "score", Type: RiskThreshold,
                Thresholds: []RiskThresholdRule{
                    {Gte: 75, Level: "HIGH"},
                    {Gte: 25, Level: "MEDIUM"},
                },
            },
        },
        Card: CardDef{
            Title: "🔧 Your Vendor", Order: 6,
            LinkTemplate: "https://yourvendor.com/{ioc}",
            LinkLabel: "↗ Your Vendor",
            Fields: []FieldDef{
                {Key: "score",  Label: "Score",  Type: FieldTypeNumber},
                {Key: "status", Label: "Status", Type: FieldTypeString},
            },
        },
        TableColumns: []TableColumn{
            {Key: "score",  Label: "YV Score",  DefaultVisible: true},
            {Key: "status", Label: "YV Status", DefaultVisible: true},
        },
    }
}

func (y YourVendor) Run(ctx context.Context, ioc, apiKey string, useCache bool) (*Result, error) {
    if useCache {
        if raw := cachedGet(ioc, "YV_IP"); raw != "" {
            var r yourVendorResponse
            if err := json.Unmarshal([]byte(raw), &r); err == nil {
                return yvToResult(&r), nil
            }
        }
    }
    r, err := fetchYourVendor(ctx, ioc, apiKey)
    if err != nil {
        return &Result{Error: err.Error()}, nil  // soft error — partial result
    }
    if b, e := json.Marshal(r); e == nil {
        cachedPut(ioc, string(b), "YV_IP")
    }
    return yvToResult(r), nil
}
```

### Step 2 — Register in `integrations/registry.go`

```go
// ── IP integrations ───────────────────────
&VirusTotalIP{},
&AbuseIPDBIntegration{},
&IPAPIIntegration{},
&ThreatFoxIPIntegration{},
&GreyNoise{},
&YourVendor{},    // <- add this line
```

**Done for domain integrations.** For IP and hash integrations, continue to Step 3.

### Step 3 — Add shim mapping (IP and hash only)

In `utils/iputil_shim.go`, add inside `buildComplexResult()`:

```go
// ── Your Vendor ───────────────────────────────────────────────────────────────
if f, ok := sr.Results["yourvendor"]; ok {
    result.YourVendor = &YVResult{
        Score:  intField(f, "score"),
        Status: strField(f, "status"),
    }
} else if errMsg, hasErr := sr.Errors["yourvendor"]; hasErr {
    result.YourVendor = &YVResult{Error: errMsg}
}
```

Also add the `YVResult` struct and a `YourVendor *YVResult` field to `ComplexResult` in `utils/iputil.go`.

> **Why is this step needed?** The scan orchestrator returns a generic `map[string]any` result. The IP and hash API responses use typed structs for backward compatibility with the frontend. This mapping block bridges them. This limitation will be removed in a future release — see [Known Limitations](#known-limitations).

### Step 4 — Add the card to the frontend

In `web/components/IOCScanner.js`, add a card inside the IP cards grid (before the `<!-- JSON panel -->` comment):

```js
<!-- Your Vendor card -->
<div v-if="activeResult.yourvendor" class="card">
  <div class="card-head">
    <span class="card-head-left">🔧 Your Vendor</span>
    <a :href="'https://yourvendor.com/'+activeResultIP"
       target="_blank" rel="noopener" class="card-source-link">↗ Your Vendor</a>
  </div>
  <div v-if="activeResult.yourvendor.score != null" class="kv">
    <span class="kv-key">Score</span>
    <span class="kv-val">{{ activeResult.yourvendor.score }}</span>
  </div>
  <div v-if="activeResult.yourvendor.status" class="kv">
    <span class="kv-key">Status</span>
    <span class="kv-val">{{ activeResult.yourvendor.status }}</span>
  </div>
  <div v-if="activeResult.yourvendor.error" class="kv mt-2">
    <span class="kv-val" style="color:var(--red);font-size:0.68rem">
      {{ activeResult.yourvendor.error }}
    </span>
  </div>
</div>
```

### Step 5 — Wire the API key (if your integration requires one)

**`web/composables/useIOCScan.js`** — add the key to the reactive state and scan request:

```js
// Add to keys reactive object
export const keys = reactive({ vt: '', abuse: '', ..., yourvendor: '' });

// Add to the /api/scan request body in doIPScan()
yourvendor_key: keys.yourvendor,
```

**`web/components/IOCScanner.js`** — add a key input to the API Keys panel:

```js
<div>
  <label ... >Your Vendor <span style="color:#2e4060">(optional)</span></label>
  <input type="password" v-model="keys.yourvendor" class="key-input"
         placeholder="Leave blank for free tier…">
</div>
```

**`server/server.go`** — add the key field to the request struct and pass it through:

```go
type scanRequest struct {
    // ... existing fields ...
    YourVendorKey string `json:"yourvendor_key"`
}

// Pass to NewIPProcessor:
processor := utils.NewIPProcessor(..., req.YourVendorKey)
```

**`utils/iputil.go`** — add to `IPProcessor` and `NewIPProcessor`:

```go
type IPProcessor struct {
    // ... existing fields ...
    yourvendorKey string
}

func NewIPProcessor(..., yourvendorKey string) *IPProcessor {
    return &IPProcessor{..., yourvendorKey: yourvendorKey}
}
```

**`utils/iputil_shim.go`** — pass the key into the keys map:

```go
keys := BuildKeys(p.vtKey, p.abuseKey, p.ipapiKey, p.abusechKey)
keys["yourvendor"] = p.yourvendorKey
```

> **Note:** This key wiring boilerplate is a known limitation. It will be eliminated when the auth system is implemented — at that point, keys come from the database and the request body only carries the scan target, not credentials.

---

## Known Limitations

### 1. Shim layer (IP and hash integrations)

IP and hash scan results pass through compatibility shims (`iputil_shim.go`, `hashutil_shim.go`) that map the generic `ScanResult` into the typed JSON structs the frontend expects. Every new IP or hash integration requires a manual mapping block (~10 lines) in the relevant shim.

Domain integrations do not have this limitation.

**Planned fix:** Remove shims when the frontend migrates to consuming `ScanResult` directly via manifests. Planned alongside the auth system.

### 2. Error card hiding

Cards that return an error (missing API key, rate limit, network failure) are hidden from the UI to avoid clutter. The raw error message is still present in the JSON panel below the cards for debugging. Cards that return a valid "not found" response (`no_results`, `hash_not_found`) still render — only hard errors are suppressed.

### 3. No authentication

The current release has no user authentication. API keys are entered in the browser per session and are not persisted between sessions. Designed for local or trusted LAN use only.

**Planned fix:** Full auth system — users, `httpOnly` session cookies, server-side AES-256-GCM encrypted API key storage. See `COMBINED_PLAN.md` for details.

### 4. Hardcoded key fields in API request

Each vendor key is a separate named field in the request body (`vt_key`, `abuse_key`, `greynoise_key`, etc.). Adding a new integration that requires a key means adding a new field to the request struct in `server/server.go`.

**Planned fix:** Replace with a generic `"keys": { "keyref": "value" }` map when the auth system is implemented (keys will come from the database, not the request body).

### 5. AbuseIPDB categories require verbose mode

Category data is only returned when the API is queried with `verbose=true` and `maxAgeInDays` set. iocscan always uses verbose mode. Category IDs are mapped to names using the [official AbuseIPDB category list](https://www.abuseipdb.com/categories) and deduplicated across all reports before display.

### 6. Domain support is VirusTotal + ThreatFox only

Domain scans query VirusTotal and ThreatFox only. Other integrations (AbuseIPDB, GreyNoise, ipapi.is) are IP-only by design. Future domain integrations (WHOIS, passive DNS, URLScan.io) can be added following the standard plugin pattern with no shim required.

### 7. SQLite concurrency

The cache database uses SQLite with WAL mode — appropriate for local and small team use. High-concurrency or multi-server deployments should migrate to PostgreSQL.

---

## Development

### Prerequisites

- Go 1.22+
- [GoReleaser](https://goreleaser.com) (release builds only)

### Run locally

```bash
git clone https://github.com/TwoA2U/iocscan.git
cd iocscan
go mod tidy
go build -o iocscan .
./iocscan
```

Open `http://localhost:8080`, enter API keys in the panel, and start scanning.

During development, iocscan reads `web/` directly from disk when the directory exists — edit frontend files and refresh without rebuilding.

### Health check

```bash
curl http://localhost:8080/api/health
# {"status":"ok","service":"iocscan"}

curl http://localhost:8080/api/integrations | jq '.[].name'
# "virustotal_ip" "abuseipdb" "ipapi" "threatfox_ip" "greynoise"
# "virustotal_hash" "malwarebazaar" "threatfox_hash"
# "virustotal_domain" "threatfox_domain"
```

### Dry-run release build

```bash
goreleaser release --snapshot --clean
```

### Tag and publish

```bash
git tag -a v1.2.0 -m "v1.2.0"
git push origin v1.2.0
```

---

## Contributing

1. Fork and create a branch off `main`
2. Commit using conventional commit messages (`feat:`, `fix:`, `docs:`)
3. Verify: `go vet ./...` and `go build ./...`
4. Open a pull request against `main`

### Good areas to contribute

- New integrations: Shodan InternetDB, OTX, Censys, URLScan — see [Adding a New Integration](#adding-a-new-integration)
- Frontend migration to manifest-driven rendering (eliminates the shim layer)
- Auth system implementation
- Additional IOC types (URLs)
- CLI improvements (coloured output, table formatting)

### Please avoid

- Breaking existing API response formats
- Hard-coded credentials of any kind
- Changes that require CGO (the project targets CGO-free static builds)
- Adding vendor-specific logic to the orchestrator — use the integration interface instead

---

## License

[MIT](LICENSE) © [TwoA2U](https://github.com/TwoA2U)