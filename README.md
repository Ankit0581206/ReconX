# ReconX 🔭

**Automated Reconnaissance Framework for Bug Bounty Hunting**

> Built during the **60-Day Challenge** — one feature added every day.

![Python](https://img.shields.io/badge/Python-3.9+-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Day](https://img.shields.io/badge/Day-1%20of%2060-brightgreen?style=flat-square)

---

## Progress

| Day | Feature | Status |
|-----|---------|--------|
| 1 | Subdomain Enumeration (crt.sh + DNS brute-force + VirusTotal) | Done |
| 2 | Port Scanner (Nmap wrapper) | Tomorrow |
| 3 | Technology Fingerprinting |  |
| 4 | Directory Discovery (FFUF wrapper) |  |
| 5 | HTML + JSON Report Generator |  |
| 6 | Discord / Telegram Notifications |  |
| 7 | Full Pipeline + Documentation |  |

---

## Installation

```bash
# Clone the repo
git clone https://github.com/Ankit0581206/ReconX.git
cd reconx

# Create virtual environment
python3 -m venv venv
source venv/bin/activate          # Linux/Mac
# venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt

# Install in dev mode (enables `reconx` command)
pip install -e .

# Copy environment file and add your API keys
cp .env.example .env
```

---

## Usage — Day 1: Subdomain Enumeration

```bash
# Basic scan (crt.sh + DNS brute-force)
reconx subs -t example.com

# Use only certificate transparency (no DNS brute-force)
reconx subs -t example.com --sources crt

# Use all sources with custom wordlist
reconx subs -t example.com \
  --sources brute,crt,virustotal \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Save results to specific file
reconx subs -t example.com -o results/example_subs.json

# Increase threads for faster brute-force
reconx subs -t example.com --threads 100
```

### Example Output

```
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
 ...

◈ SUBDOMAIN ENUMERATION
────────────────────────
  →  Target     : example.com
  →  Sources    : brute, crt, virustotal
  →  Threads    : 50

  ✓  api.example.com                           93.184.216.34    [crt.sh]
  ✓  mail.example.com                          93.184.216.34    [brute]
  ✓  dev.example.com                           93.184.216.100   [crt.sh]  → CNAME: dev.example.com.cdn.cloudflare.net

╭────────────────────────────────────────╮
│   Subdomain Enumeration Complete       │
│                                        │
│   Target             example.com       │
│   Total found        47                │
│   Sources used       brute, crt        │
│   Time elapsed       12.4s             │
│   Wordlist entries   200               │
╰────────────────────────────────────────╯

  →  Results saved → output/example_com_subs_20240101_120000.json
```

### JSON Output Structure

```json
{
  "target": "example.com",
  "module": "subdomains",
  "timestamp": "2024-01-01T12:00:00Z",
  "elapsed_sec": 12.4,
  "count": 47,
  "results": [
    {
      "name": "api.example.com",
      "ip": "93.184.216.34",
      "source": "crt.sh",
      "status": "alive",
      "cname": ""
    }
  ]
}
```

---

## Project Structure

```
reconx/
├── reconx/
│   ├── cli.py              # Click CLI — entry point
│   ├── modules/
│   │   └── subdomains.py   # Day 1: Subdomain enumerator
│   └── utils/
│       └── output.py       # Rich terminal output helpers
├── wordlists/
│   └── subdomains.txt      # Default 200-entry wordlist
├── output/                 # Scan results saved here
├── .env.example            # API key template
├── requirements.txt
├── setup.py
└── README.md
```

---

## API Keys (Optional)

Add to your `.env` file for enhanced results:

| Service | Variable | Free Tier |
|---------|----------|-----------|
| VirusTotal | `VIRUSTOTAL_API_KEY` | 500 req/day |
| SecurityTrails | `SECURITYTRAILS_API_KEY` | 50 req/month |

crt.sh works with **no API key** and is the most reliable source.

---

## Get Better Wordlists

```bash
# Install SecLists (Kali/Parrot/Arch)
sudo apt install seclists

# Use the 5000-entry DNS wordlist
reconx subs -t target.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Or the massive 1 million entry list (slow but thorough)
reconx subs -t target.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million.txt \
  --threads 100
```

---

*Built as part of the 60-Day Challenge — Day 1/60*
