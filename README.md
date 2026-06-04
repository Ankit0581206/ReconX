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
| 2 | Port Scanner (Nmap wrapper) | Done |
| 3 | Technology Fingerprinting | Done |
| 4 | Directory Discovery (FFUF wrapper) | Done |
| 5 | HTML + JSON Report Generator | Tomorrow |
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

## Usage — Day 2: Port Scanner
```bash
# Quick test — top 20 ports
reconx ports -t testphp.vulnweb.com --top 20 --skip-ping --no-banner

# Specific ports (fast)
reconx ports -t 44.228.249.3 -p 22,80,443,3306,6379,27017 --skip-ping

# Full top-1000 scan (takes ~2 min)
reconx ports -t vulnweb.com --top 1000 --skip-ping

```
## Usage — Day 3: Tech Fingerprinter
```bash
# Scan any domain — auto-adds https://
reconx tech -t vulnweb.com --no-banner

# Full URL
reconx tech -t https://testphp.vulnweb.com --no-banner

# Save results to a specific file
reconx tech -t vulnweb.com -o output/vulnweb_tech.json --no-banner

# Don't follow redirects
reconx tech -t vulnweb.com --no-redirect --no-banner

# Increase timeout for slow targets
reconx tech -t vulnweb.com --timeout 20 --no-banner

```
## Usage — Day 4: directory discovery
```bash

# Basic scan — built-in 212-entry wordlist
reconx dirs -t vulnweb.com --no-banner

# Add file extensions (great for PHP/ASP sites)
reconx dirs -t vulnweb.com -x php,bak,txt,json --no-banner

# Scan a specific path (e.g. the API)
reconx dirs -t vulnweb.com/api --no-banner

# Use SecLists for deeper coverage (Garuda has it)
reconx dirs -t vulnweb.com \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  --threads 80 --no-banner

```

## Project Structure

```
reconx/
├── reconx/
│   ├── cli.py              # Click CLI — entry point
│   ├── modules/
│   │   ├── subdomains.py   # Day 1: Subdomain enumerator
        ├── Ports.py        # Day 2: port scanner with service detection and risk ratings
        ├── tech.py         # Day 3: technology fingerprinter — CMS, WAF, CDN, security headers
        └── tech.py         # Day 4: directory discovery with soft-404 filter and interesting path detection
│   └── utils/
│       └── output.py       # Rich terminal output helpers
├── wordlists/
    ├── directories.txt     # Directory & Endpoint Wordlist ~300 entries: common dirs, files, API paths, sensitive files
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

*Built as part of the 60-Day Challenge*
