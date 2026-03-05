# iocscan

[![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/TwoA2U/iocscan)](https://github.com/TwoA2U/iocscan/releases/latest)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macOS%20%7C%20windows-lightgrey)](#supported-platforms)

**Fast, multi-source threat intelligence enrichment for IP addresses and file hashes.**

Query IPs and file hashes against VirusTotal, AbuseIPDB, ipapi.is, and MalwareBazaar — from the terminal or a local web UI. Ships as a single self-contained binary with no runtime dependencies.

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Web UI](#web-ui)
- [CLI Reference](#cli-reference)
- [Output Format](#output-format)
- [Data Sources](#data-sources)
- [Supported Platforms](#supported-platforms)
- [Project Structure](#project-structure)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **IP enrichment** — geo, ASN, abuse confidence score, and VirusTotal verdicts
- **Hash enrichment** — VirusTotal detections, MalwareBazaar intel, code signing validation, Sigma rule hits, sandbox classifications
- **Web UI** — interactive scanner with cards/table views, column visibility toggles, export to CSV/JSON, scan history
- **CLI** — pipe-friendly JSON output for scripting and automation
- **Bulk scanning** — up to 20 IPs or 100 hashes per request
- **Local cache** — SQLite-backed caching to avoid redundant API calls and respect rate limits
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
    ┌────┴──────────────────────────┐
    │         │          │          │
    ▼         ▼          ▼          ▼
 ipapi.is  AbuseIPDB  VirusTotal  MalwareBazaar
 geo/ASN   abuse      multi-      malware
           score      engine      samples
                      verdicts    (hashes only)
    │         │          │          │
    └────┬──────────────────────────┘
         │  merge + compute riskLevel
         ▼
   JSON result (CLI output or Web UI)
         │
         ▼
   SQLite cache (optional, per-scan)
```

IPs and hashes are enriched concurrently across all configured sources. Results are merged into a single normalised JSON structure with a computed `riskLevel` (`CLEAN` → `CRITICAL`). Responses are optionally cached in a local SQLite database to avoid burning API quota on repeated lookups.

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
iocscan -v <VIRUSTOTAL_KEY> -a <ABUSEIPDB_KEY> -i <IPAPI_KEY> -m <MALWAREBAZAAR_KEY>
```

| Flag | Source | Required |
|------|--------|----------|
| `-v` | [VirusTotal](https://www.virustotal.com/gui/my-apikey) | Yes (complex mode + hash scans) |
| `-a` | [AbuseIPDB](https://www.abuseipdb.com/account/api) | Yes (complex mode) |
| `-i` | [ipapi.is](https://ipapi.is/developers.html) | No — free tier works without a key |
| `-m` | [MalwareBazaar](https://bazaar.abuse.ch/api/) | No — public lookups work without a key |

Keys are stored locally and reused on every subsequent scan. They are never sent anywhere except the respective API endpoints.

### 2. Scan

```bash
# Start the web UI (recommended)
iocscan web

# Simple IP lookup — geo & ASN only
iocscan ips -i 8.8.8.8

# Complex IP enrichment — AbuseIPDB + VirusTotal + geo
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

**IP mode** enriches against ipapi.is, AbuseIPDB, and VirusTotal.  
**Hash mode** enriches against VirusTotal and MalwareBazaar.

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

## CLI Reference

```
iocscan [command] [flags]

Commands:
  ips    Simple IP lookup — geo & ASN only (ipapi.is)
  ipc    Complex IP enrichment — AbuseIPDB + VirusTotal + geo
  web    Start the web UI

Global Flags:
  -v, --VT_API      VirusTotal API key
  -a, --Abuse_API   AbuseIPDB API key
  -i, --IPapi_API   ipapi.is API key (optional)
  -m, --MB_API      MalwareBazaar Auth-Key (optional)
  -c, --config      Config file path (default: ~/.iocscan.yaml)
  -h, --help        Help
```

### Examples

```bash
# Simple lookup — fast, no VT/AbuseIPDB quota used
iocscan ips -i 1.2.3.4

# Full threat intel enrichment
iocscan ipc -i 1.2.3.4

# Multiple IPs, pipe to jq to extract risk levels
iocscan ipc -i "1.2.3.4, 5.6.7.8" | jq '.[].result.riskLevel'

# Filter only critical/high risk IPs
iocscan ipc -i "1.2.3.4, 5.6.7.8" | \
  jq '[.[] | select(.result.riskLevel | test("CRITICAL|HIGH"))]'

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
    "ip": "1.2.3.4",
    "result": {
      "ipAddress": "1.2.3.4",
      "isp": "Example ISP Ltd",
      "country": "United States",
      "countryCode": "US",
      "city": "San Jose",
      "state": "California",
      "timezone": "America/Los_Angeles",
      "isPublic": true,
      "isWhitelisted": false,
      "abuseConfidenceScore": 87,
      "totalReports": 142,
      "lastReportedAt": "2024-11-20T14:33:00+00:00",
      "vtMalicious": 4,
      "vtSuspicious": 1,
      "vtReputation": -12,
      "riskLevel": "HIGH",
      "links": {
        "ipapi": "https://api.ipapi.is/?q=1.2.3.4",
        "abuseipdb": "https://www.abuseipdb.com/check/1.2.3.4",
        "virustotal": "https://www.virustotal.com/gui/ip-address/1.2.3.4"
      }
    }
  }
]
```

### Hash enrichment

```json
[
  {
    "hash": "d55f983c994caa160ec63a59f6b4250fe67fb3e8c43a388aec60a4a6978e9f1e",
    "result": {
      "hashType": "SHA256",
      "riskLevel": "CRITICAL",
      "md5": "561cffbaba71a6e8cc1cdceda990ead4",
      "sha1": "5162f14d75e96edb914d1756349d6e11583db0b0",
      "sha256": "d55f983c994caa160ec63a59f6b4250fe67fb3e8c43a388aec60a4a6978e9f1e",
      "meaningfulName": "revil_dll.dll",
      "magic": "PE32 executable (GUI) Intel 80386, for MS Windows",
      "magika": "PEBIN",
      "vtMalicious": 58,
      "vtSuspicious": 0,
      "vtHarmless": 0,
      "vtUndetected": 10,
      "vtReputation": -436,
      "suggestedThreatLabel": "trojan.sodinokibi/revil",
      "popularThreatNames": ["sodinokibi", "revil", "dangeroussig"],
      "popularThreatCategories": ["trojan", "ransomware", "dropper"],
      "sandboxMalwareClassifications": ["MALWARE", "RANSOM", "EVADER"],
      "sigmaAnalysisSummary": {
        "Sigma Integrated Rule Set (GitHub)": {
          "critical": 1,
          "high": 1,
          "medium": 2,
          "low": 0
        }
      },
      "signatureSigners": "PB03 TRANSPORT LTD.; Sectigo RSA Code Signing CA",
      "signerDetail": {
        "certIssuer": "Sectigo RSA Code Signing CA",
        "name": "PB03 TRANSPORT LTD.",
        "status": "Trust for this certificate has been revoked.",
        "validFrom": "12:00 AM 04/29/2021",
        "validTo": "11:59 PM 04/29/2022"
      },
      "mbQueryStatus": "ok",
      "mbSignature": "Sodinokibi",
      "mbFileName": "revil.exe",
      "mbFileType": "exe",
      "mbTags": ["exe", "revil", "signed", "Sodinokibi"],
      "mbComment": "Found from the Kaseya Reddit threat, speculated to impact 200+ orgs",
      "links": {
        "virustotal": "https://www.virustotal.com/gui/file/d55f983c...",
        "malwarebazaar": "https://bazaar.abuse.ch/sample/d55f983c..."
      }
    }
  }
]
```

### Risk levels

| Level | Meaning |
|-------|---------|
| `CLEAN` | No detections across all sources |
| `LOW` | Minor indicators, likely benign |
| `MEDIUM` | Some detections or moderate abuse score |
| `HIGH` | Significant detections or high abuse score |
| `CRITICAL` | Confirmed malicious across multiple sources |

---

## Data Sources

| Source | Used For | Free Tier |
|--------|----------|-----------|
| [ipapi.is](https://ipapi.is) | Geo, ASN, datacenter/VPN detection | 1,000 req/day without a key |
| [AbuseIPDB](https://www.abuseipdb.com) | Abuse confidence score, report history | 1,000 req/day |
| [VirusTotal](https://www.virustotal.com) | Multi-engine verdicts for IPs and hashes | 4 req/min, 500 req/day |
| [MalwareBazaar](https://bazaar.abuse.ch) | Malware sample metadata, tags, signatures | Public API, no hard limit |

All sources are queried concurrently per indicator. Results are merged and optionally cached locally to minimise repeat API usage.

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
├── main.go              — entry point
├── cmd/                 — CLI subcommands
│   ├── root.go          — API key management, config
│   ├── ips.go           — ips subcommand (simple lookup)
│   ├── ipc.go           — ipc subcommand (complex enrichment)
│   └── web.go           — web subcommand (HTTP server + handlers)
├── utils/               — enrichment logic
│   ├── iputil.go        — IP lookup (ipapi.is, AbuseIPDB, VirusTotal)
│   ├── hashutil.go      — hash lookup (VirusTotal, MalwareBazaar)
│   ├── iocutil.go       — shared IOC helpers
│   └── common.go        — config, SQLite cache, API key helpers
├── ui/
│   └── ui.go            — embeds web/index.html into the binary
└── web/
    └── index.html       — Vue 3 single-page web UI
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
./iocscan -v <VT_KEY> -a <ABUSE_KEY>

# Start the web UI
./iocscan web
```

During development, `iocscan web` reads `web/index.html` directly from disk — edit the file and refresh the browser without rebuilding. In production (or when the file is absent on disk), the version embedded at compile time is served.

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

- New threat intelligence sources
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