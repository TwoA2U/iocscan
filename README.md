# iocscan

[![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/TwoA2U/iocscan)](https://github.com/TwoA2U/iocscan/releases/latest)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macOS%20%7C%20windows-lightgrey)](#supported-platforms)

**Fast, multi-source threat intelligence enrichment for IP addresses and file hashes.**

Query IPs and file hashes against VirusTotal, AbuseIPDB, ThreatFox, ipapi.is, and MalwareBazaar — from the terminal or a local web UI. Ships as a single self-contained binary with no runtime dependencies.

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Web UI](#web-ui)
- [API Reference](#api-reference)
- [CLI Reference](#cli-reference)
- [Output Format](#output-format)
- [Risk Scoring](#risk-scoring)
- [Data Sources](#data-sources)
- [Supported Platforms](#supported-platforms)
- [Project Structure](#project-structure)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **IP enrichment** — geo, ASN, abuse confidence score, VirusTotal verdicts, and ThreatFox C2 intelligence
- **Hash enrichment** — VirusTotal detections, MalwareBazaar intel, code signing validation, Sigma rule hits, sandbox classifications
- **Multi-signal risk scoring** — `riskLevel` is computed from AbuseIPDB score, VT malicious count, and ThreatFox confidence level combined
- **Web UI** — interactive scanner with cards/table views, column visibility toggles, export to CSV/JSON, scan history
- **CLI** — pipe-friendly JSON output for scripting and automation
- **Bulk scanning** — up to 20 IPs or 100 hashes per request
- **Local cache** — SQLite-backed caching across all sources (including geo) to avoid redundant API calls and respect rate limits
- **Rate limiting** — built-in token-bucket limiter protects vendor API quota on the web server
- **Single binary** — web UI is embedded at compile time, no external files needed

---

## How It Works

```
  Input (IP or Hash)
        │
        ▼
  ┌─────────────┐
  │   iocscan   │  CLI or Web UI
  └──────┬──────┘
         │  concurrent requests
    ┌────┴──────────────────────────────┐
    │         │          │              │
    ▼         ▼          ▼              ▼
 ipapi.is  AbuseIPDB  VirusTotal    ThreatFox
 geo/ASN   abuse      multi-engine  C2/botnet
           score      verdicts      IOC intel
                      (IP + hash)   (IP + hash)
    │         │          │              │
    └────┬──────────────────────────────┘
         │  merge + compute riskLevel
         │  (AbuseIPDB score + VT malicious + ThreatFox confidence)
         ▼
   JSON result (CLI output or Web UI)
         │
         ▼
   SQLite cache (optional, per-scan)
```

All sources are queried concurrently per indicator. Results are merged into a single normalised JSON structure with a computed `riskLevel` (`CLEAN` → `CRITICAL`). Responses are optionally cached in a local SQLite database to avoid burning API quota on repeated lookups.

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

Requires Go 1.21+.

```bash
git clone https://github.com/TwoA2U/iocscan.git
cd iocscan
go build -o iocscan .
```

---

## Quick Start

### 1. Save your API keys

Run once to persist keys to `~/.iocscan.yaml`:

```bash
iocscan -v <VIRUSTOTAL_KEY> -a <ABUSEIPDB_KEY> -i <IPAPI_KEY> -b <ABUSECH_KEY>
```

| Flag | Source | Required |
|------|--------|----------|
| `-v` | [VirusTotal](https://www.virustotal.com/gui/my-apikey) | Yes (complex mode + hash scans) |
| `-a` | [AbuseIPDB](https://www.abuseipdb.com/account/api) | Yes (complex mode) |
| `-i` | [ipapi.is](https://ipapi.is/developers.html) | No — free tier works without a key |
| `-b` | [abuse.ch](https://bazaar.abuse.ch/api/) | No — used for both MalwareBazaar and ThreatFox |

Keys are stored locally and reused on every subsequent scan. They are never sent anywhere except the respective API endpoints.

### 2. Scan

```bash
# Start the web UI (recommended)
iocscan web

# Full IP enrichment — AbuseIPDB + VirusTotal + ThreatFox + geo
iocscan ipc -i 8.8.8.8

# Multiple IPs (comma-separated)
iocscan ipc -i "8.8.8.8, 1.1.1.1, 9.9.9.9"
```

---

## Web UI

```bash
iocscan web              # http://localhost:8080
iocscan web --port 9090  # custom port
```

The web UI is embedded inside the binary — no separate files required. Open your browser after starting the server.

**IP mode** enriches against ipapi.is, AbuseIPDB, VirusTotal, and ThreatFox.  
**Hash mode** enriches against VirusTotal, MalwareBazaar, and ThreatFox.

| Feature | Description |
|---------|-------------|
| Cards view | Per-indicator detail cards with risk badges and source links |
| Table view | Sortable multi-indicator comparison table |
| Column toggles | Show/hide individual fields per section |
| Bulk input | Paste multiple indicators or upload a `.txt` / `.csv` file |
| Export | Download results as CSV or JSON |
| Copy | Copy to clipboard as JSON, CSV, or raw indicators only |
| Scan history | Last 20 scans with one-click re-scan |
| Cache toggle | Per-scan control over SQLite result caching |

---

## API Reference

The web server exposes the following endpoints. All API responses use `Content-Type: application/json`, including errors.

### `GET /api/health`

Health check endpoint. Returns HTTP 200 when the server is running.

```json
{ "status": "ok" }
```

### `POST /api/scan`

IP enrichment. Accepts a single IP or comma-separated list.

```json
{
  "ip": "1.2.3.4",
  "vt_key": "...",
  "abuse_key": "...",
  "ipapi_key": "...",
  "abusech_key": "...",
  "use_cache": true
}
```

Keys are optional if they have been saved via the CLI. Returns a JSON array — one entry per IP.

### `POST /api/scan/hash`

Hash enrichment. Accepts up to 100 hashes (MD5, SHA1, or SHA256).

```json
{
  "hashes": ["<hash1>", "<hash2>"],
  "vt_key": "...",
  "abusech_key": "...",
  "use_cache": true
}
```

### `POST /api/scan/ioc`

Mixed IOC enrichment. Accepts a list of mixed indicators — IPs and hashes are auto-detected and routed to the correct pipeline.

```json
{
  "iocs": ["1.2.3.4", "<sha256>", "5.6.7.8"],
  "vt_key": "...",
  "abuse_key": "...",
  "ipapi_key": "...",
  "abusech_key": "...",
  "use_cache": true
}
```

### `POST /api/cache/clear`

Clear cached results. Pass a specific table name or `"all"` to wipe everything.

```json
{ "table": "all" }
```

Valid table names: `VT_IP`, `ABUSE_IP`, `IPAPIIS_IP`, `VT_HASH`, `MB_HASH`, `TF_IP`, `TF_HASH`.

### Error responses

All errors return a consistent JSON body:

```json
{ "error": "description of what went wrong" }
```

---

## CLI Reference

```
iocscan [command] [flags]

Commands:
  ipc    Full IP enrichment — AbuseIPDB + VirusTotal + ThreatFox + geo
  web    Start the web UI

Global Flags:
  -v, --VT_API        VirusTotal API key
  -a, --Abuse_API     AbuseIPDB API key
  -i, --IPapi_API     ipapi.is API key (optional)
  -b, --AbuseCH_API   abuse.ch key — MalwareBazaar + ThreatFox (optional)
  -c, --config        Config file path (default: ~/.iocscan.yaml)
  -h, --help          Help
```

### Examples

```bash
# Full threat intel enrichment
iocscan ipc -i 1.2.3.4

# Multiple IPs, pipe to jq to extract risk levels
iocscan ipc -i "1.2.3.4, 5.6.7.8" | jq '.[].riskLevel'

# Filter only critical/high risk IPs
iocscan ipc -i "1.2.3.4, 5.6.7.8" | \
  jq '[.[] | select(.riskLevel | test("CRITICAL|HIGH"))]'

# Use a custom config file
iocscan ipc -i 1.2.3.4 --config /path/to/keys.yaml

# Start web UI on a custom port
iocscan web --port 9090
```

---

## Output Format

All CLI commands output a JSON array. Each element contains the queried indicator and its enriched result.

### IP enrichment (complex mode)

```json
[
   {
      "ipAddress": "45.77.34.87",
      "riskLevel": "CRITICAL",
      "links": {
         "ipapi": "https://api.ipapi.is/?q=45.77.34.87",
         "abuseipdb": "https://www.abuseipdb.com/check/45.77.34.87",
         "virustotal": "https://www.virustotal.com/gui/ip-address/45.77.34.87"
      },
      "geo": {
         "isp": "Vultr Holdings, LLC",
         "country": "Singapore",
         "countryCode": "SG",
         "city": "Singapore",
         "timezone": "Asia/Singapore",
         "isPublic": true,
         "isWhitelisted": false,
         "hostnames": ["45.77.34.87.vultrusercontent.com"]
      },
      "virustotal": {
         "malicious": 5,
         "suspicious": 1,
         "undetected": 36,
         "harmless": 54,
         "reputation": -11
      },
      "abuseipdb": {
         "confidenceScore": 82,
         "totalReports": 14
      },
      "threatfox": {
         "queryStatus": "ok",
         "threatType": "botnet_cc",
         "malware": "win.cobalt_strike",
         "confidenceLevel": 100,
         "firstSeen": "2026-03-06 08:01:28 UTC",
         "reporter": "abuse_ch",
         "tags": ["CobaltStrike", "c2"]
      }
   }
]
```

### Hash enrichment

```json
[
   {
      "hash": "d55f983c994caa160ec63a59f6b4250fe67fb3e8c43a388aec60a4a6978e9f1e",
      "hashType": "SHA256",
      "riskLevel": "CRITICAL",
      "links": {
         "virustotal": "https://www.virustotal.com/gui/file/d55f983c994caa160ec63a59f6b4250fe67fb3e8c43a388aec60a4a6978e9f1e",
         "malwarebazaar": "https://bazaar.abuse.ch/sample/d55f983c994caa160ec63a59f6b4250fe67fb3e8c43a388aec60a4a6978e9f1e"
      },
      "virustotal": {
         "md5": "561cffbaba71a6e8cc1cdceda990ead4",
         "sha1": "5162f14d75e96edb914d1756349d6e11583db0b0",
         "sha256": "d55f983c994caa160ec63a59f6b4250fe67fb3e8c43a388aec60a4a6978e9f1e",
         "meaningfulName": "revil.exe",
         "malicious": 58,
         "suspicious": 0,
         "undetected": 10,
         "reputation": -436,
         "suggestedThreatLabel": "trojan.sodinokibi/revil"
      },
      "malwarebazaar": {
         "queryStatus": "ok",
         "fileName": "revil.exe",
         "fileType": "exe",
         "signature": "Sodinokibi",
         "tags": ["revil", "Sodinokibi", "signed"]
      }
   }
]
```

---

## Risk Scoring

`riskLevel` is computed from three independent signals. Any single signal is sufficient to escalate the level — a confirmed ThreatFox C2 hit will raise the risk even if AbuseIPDB and VirusTotal show nothing yet.

| Level | AbuseIPDB score | VT malicious engines | ThreatFox confidence |
|-------|:-:|:-:|:-:|
| `CRITICAL` | ≥ 75 | ≥ 5 | ≥ 75 |
| `HIGH` | ≥ 40 | ≥ 2 | ≥ 50 |
| `MEDIUM` | ≥ 10 | ≥ 1 | > 0 |
| `LOW` | > 0 | — | — |
| `CLEAN` | 0 | 0 | 0 |

Thresholds are defined in `utils/iputil.go` (`assessRisk` function) and can be adjusted to suit your environment.

---

## Data Sources

| Source | Used For | Free Tier |
|--------|----------|-----------|
| [ipapi.is](https://ipapi.is) | Geo, ASN, datacenter/VPN detection | 1,000 req/day without a key |
| [AbuseIPDB](https://www.abuseipdb.com) | Abuse confidence score, report history | 1,000 req/day |
| [VirusTotal](https://www.virustotal.com) | Multi-engine verdicts for IPs and hashes | 4 req/min, 500 req/day |
| [MalwareBazaar](https://bazaar.abuse.ch) | Malware sample metadata, tags, signatures | Public API, no hard limit |
| [ThreatFox](https://threatfox.abuse.ch) | C2/botnet IOC intelligence for IPs and hashes | Public API, no hard limit |

All sources are queried concurrently per indicator. Results are merged and cached locally to minimise repeat API usage. Cache covers all five sources including geo lookups.

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
├── main.go                  — entry point, embeds web/ at compile time
├── cmd/                     — CLI commands
│   ├── ipc.go               — ipc subcommand (full IP enrichment)
│   ├── root.go              — root command, CLI configuration
│   └── web.go               — web server, HTTP handlers, rate limiting
├── dist/                    — build artifacts / release output
├── integrations/            — threat intelligence vendor integrations
│   ├── abuseipdb.go         — AbuseIPDB API integration
│   ├── ipapi.go             — IP geolocation lookup (ipapi.is)
│   ├── malwarebazaar.go     — MalwareBazaar hash lookup
│   ├── threatfox.go         — ThreatFox IOC lookup (IPs and hashes)
│   └── virustotal.go        — VirusTotal API integration (IPs and hashes)
├── internal/
│   └── httpclient/          — shared HTTP client with context support
│       └── http.go
├── utils/                   — enrichment logic and helpers
│   ├── common.go            — config, cache helpers, shared types
│   ├── hashutil.go          — hash enrichment orchestration
│   ├── iocutil.go           — IOC type detection and validation
│   └── iputil.go            — IP enrichment orchestration, risk scoring
└── web/                     — Vue 3 + TailwindCSS web UI
    ├── components/
    │   ├── ColumnDrawer.js  — column visibility drawer
    │   ├── IOCScanner.js    — main scanner component
    │   └── ResultsTable.js  — sortable results table
    ├── composables/
    │   ├── useColumnVisibility.js — column toggle state
    │   ├── useHashResults.js      — hash result state and export logic
    │   ├── useIOCScan.js          — scan submission and polling
    │   ├── useIPResults.js        — IP result state and export logic
    │   ├── useScanHistory.js      — scan history management
    │   └── utils.js               — shared helpers (highlight, download, escapeHTML)
    ├── index.html           — main UI entry point
    └── main.js              — Vue app bootstrap
```

---

## Development

### Prerequisites

- Go 1.21+
- [GoReleaser](https://goreleaser.com) (for release builds only)

### Run locally

```bash
git clone https://github.com/TwoA2U/iocscan.git
cd iocscan
go mod tidy
go build -o iocscan .

# Save API keys
./iocscan -v <VT_KEY> -a <ABUSE_KEY> -b <ABUSECH_KEY> -i <IPAPIIS_KEY>

# Start the web UI
./iocscan web
```

During development, `iocscan web` reads `web/index.html` directly from disk — edit the file and refresh the browser without rebuilding. In production (or when the file is absent on disk), the version embedded at compile time is served.

### Health check

```bash
curl http://localhost:8080/api/health
# {"status":"ok"}
```

### Dry-run release build

Test the full GoReleaser pipeline locally without publishing:

```bash
goreleaser release --snapshot --clean
```

Binaries land in `dist/` for inspection.

### Tag and publish a release

```bash
git tag -a v1.0.0 -m "v1.0.0"
git push origin v1.0.0
```

GitHub Actions picks up the tag and runs GoReleaser automatically.

---

## Contributing

Contributions are welcome. Please follow these steps:

1. **Fork** the repository and create a branch off `main`:
   ```bash
   git checkout -b feat/your-feature
   ```

2. **Commit** using conventional commit messages:
   ```
   feat: add new threat intel source
   fix: handle nil pointer in hash enrichment
   docs: update CLI reference
   ```

3. **Verify** your changes build and vet cleanly:
   ```bash
   go vet ./...
   go build ./...
   ```

4. **Open a pull request** against `main` with a clear description of what changed and why.

### Good areas to contribute

- New threat intelligence sources (Shodan, GreyNoise, OTX, Censys)
- CLI output improvements (colour, table formatting)
- Web UI features or bug fixes
- Performance improvements to concurrent enrichment
- Additional hash type support

### Please avoid

- Breaking existing API endpoints or CLI flags
- Hard-coded credentials of any kind
- Changes that require CGO (the project targets CGO-free static builds)

---

## License

[MIT](LICENSE) © [TwoA2U](https://github.com/TwoA2U)