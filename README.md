# 🛡️ iocscan

[![Go Version](https://img.shields.io/github/go-mod/go-version/TwoA2U/iocscan)](https://golang.org)
[![Release](https://img.shields.io/github/v/release/TwoA2U/iocscan)](https://github.com/TwoA2U/iocscan/releases)
[![License](https://img.shields.io/github/license/TwoA2U/iocscan)](./LICENSE)

`iocscan` is a lightweight **Incident Response (IR) & Threat Intelligence helper CLI** written in Go.  
It helps analysts and defenders quickly **query IP addresses, check for abuse reports, and gather enrichment data** from multiple sources (AbuseIPDB, VirusTotal, ipapi.is, etc.).

---

## ✨ Features

- 🔎 **IP lookup** via [ipapi.is](https://ipapi.is)  
- 🚨 **Threat intelligence enrichment** with [AbuseIPDB](https://www.abuseipdb.com/)  
- 🧪 **Malicious activity check** using [VirusTotal](https://www.virustotal.com/)  
- ⚡ Built with [Cobra](https://github.com/spf13/cobra) — modern CLI experience  
- 📦 Cross-platform (Linux, Windows, macOS) single binary  
- 🧹 Minimal output modes:
  - **Simple** (`ips`) → quick info
  - **Complex** (`ipc`) → detailed multi-source enrichment  

---

## 📦 Installation

### From Releases
Download the latest binary from [Releases](https://github.com/TwoA2U/iocscan/releases):

#### Linux
```bash
wget https://github.com/TwoA2U/iocscan/releases/download/v0.1.0/iocscan_Linux_x86_64.tar.gz
tar -xvzf iocscan_Linux_x86_64.tar.gz
sudo mv iocscan /usr/local/bin/
```

#### Windows (PowerShell)
```powershell
Invoke-WebRequest -Uri https://github.com/TwoA2U/iocscan/releases/download/v0.1.0/iocscan_Windows_x86_64.zip -OutFile iocscan.zip
Expand-Archive iocscan.zip -DestinationPath .
```

### From Source
git clone git@github.com:TwoA2U/iocscan.git
cd iocscan
go build -o iocscan .

## ⚡ Usage

### Initiate API
```
iocscan.exe -v "Virus total API" -a "AbuseIPDB API" -i "IPapiis API"
```

### Subcommand ips
```bash
iocscan ips -i "8.8.8.8"
```

### Example output
```json
[
{
  "ip": "8.8.8.8",
  "company_name": "Google LLC",
  "company_type": "hosting",
  "asn_org": "Google LLC",
  "country": "United States",
  "state": "California",
  "city": "San Jose",
  "timezone": "America/Los_Angeles"
},
]
```

### Subcommand ipc
```bash
iocscan ipc -i "8.8.8.8"
```

### Example output
```json
[
{
  "ipAddress": "8.8.8.8",
  "hostnames": [
    "dns.google"
  ],
  "isp": "Google LLC",
  "isPublic": true,
  "isWhitelisted": true,
  "countryCode": "US",
  "vtStats_S_U_H": "0/32/62",
  "totalReports": 42,
  "abuseConfidenceScore": 0,
  "vtMalicious": 0
},
]
```

## 🛠️ Development
### Project structure:
```
iocscan/
├── cmd/          # CLI commands (Cobra)
│   ├── root.go
│   ├── ips.go
│   └── ipc.go
├── util/         # utility packages
│   └── iputil.go
├── go.mod
└── main.go
```

### Project structure:
```
go run main.go ips -i 1.1.1.1
```

🚀 Roadmap
- Add file & hash scanning against VirusTotal / Hybrid Analysis
- Support CSV bulk lookups
- Add JSON/CSV export options



