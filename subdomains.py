"""
ReconX Module: Subdomain Enumerator
Day 1 — 60-Day Bug Bounty Challenge

Techniques used:
  1. DNS brute-force    — tries wordlist entries against target domain
  2. Certificate transparency  — queries crt.sh for known subdomains
  3. VirusTotal passive DNS   — queries VT if API key is set

Usage:
    from reconx.modules.subdomains import SubdomainEnumerator
    enumerator = SubdomainEnumerator(target="example.com", wordlist="wordlists/subdomains.txt")
    results = enumerator.run()
"""

import os
import time
import json
import socket
import threading
from pathlib import Path
from typing import Callable
from dataclasses import dataclass, field, asdict

import dns.resolver
import requests
from dotenv import load_dotenv

from reconx.utils.output import console, section_header, found, info, warn, error

load_dotenv()

# ─────────────────────────────────────────────────────────────
# Data Model
# ─────────────────────────────────────────────────────────────

@dataclass
class Subdomain:
    """Represents a single discovered subdomain."""
    name: str                       # Full subdomain e.g. api.example.com
    ip: str = ""                    # Resolved IP address
    source: str = ""                # Where it was found: brute/crt/virustotal
    status: str = "alive"           # alive | unresolvable
    cname: str = ""                 # CNAME record if present (takeover detection hint)
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# ─────────────────────────────────────────────────────────────
# SubdomainEnumerator
# ─────────────────────────────────────────────────────────────

class SubdomainEnumerator:
    """
    Discovers subdomains for a target domain using multiple techniques.

    Args:
        target      : Root domain to enumerate (e.g. "example.com")
        wordlist    : Path to subdomain wordlist file
        threads     : Number of concurrent DNS threads (default 50)
        timeout     : DNS query timeout in seconds (default 2)
        sources     : List of techniques to use: brute, crt, virustotal
        on_found    : Optional callback called with each Subdomain as found
    """

    DEFAULT_WORDLIST = Path(__file__).parent.parent.parent / "wordlists" / "subdomains.txt"

    def __init__(
        self,
        target: str,
        wordlist: str | None = None,
        threads: int = 50,
        timeout: float = 2.0,
        sources: list[str] | None = None,
        on_found: Callable[[Subdomain], None] | None = None,
    ):
        self.target   = target.lower().strip().removeprefix("http://").removeprefix("https://").rstrip("/")
        self.wordlist = Path(wordlist) if wordlist else self.DEFAULT_WORDLIST
        self.threads  = threads
        self.timeout  = timeout
        self.sources  = sources or ["brute", "crt", "virustotal"]
        self.on_found = on_found

        self.results: list[Subdomain] = []
        self._seen: set[str] = set()          # dedup set
        self._lock = threading.Lock()

        # Configure DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout       = timeout
        self.resolver.lifetime      = timeout
        self.resolver.nameservers   = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]

    # ── Public API ───────────────────────────────────────────

    def run(self) -> list[Subdomain]:
        """Run all enabled enumeration sources and return combined results."""
        section_header("Subdomain Enumeration", "🔭")
        info(f"Target     : [accent]{self.target}[/accent]")
        info(f"Sources    : [accent]{', '.join(self.sources)}[/accent]")
        info(f"Threads    : [accent]{self.threads}[/accent]")

        start = time.time()

        if "crt" in self.sources:
            self._run_crt_sh()

        if "virustotal" in self.sources:
            self._run_virustotal()

        if "brute" in self.sources:
            self._run_bruteforce()

        elapsed = time.time() - start

        from reconx.utils.output import summary_panel
        summary_panel("Subdomain Enumeration Complete", {
            "Target":           self.target,
            "Total found":      str(len(self.results)),
            "Sources used":     ", ".join(self.sources),
            "Time elapsed":     f"{elapsed:.1f}s",
            "Wordlist entries": str(self._wordlist_size()) if "brute" in self.sources else "N/A",
        })

        return self.results

    # ── Source: Certificate Transparency (crt.sh) ────────────

    def _run_crt_sh(self):
        """Query crt.sh certificate transparency logs — no API key needed."""
        info("Querying crt.sh certificate transparency logs...")
        url = f"https://crt.sh/?q=%.{self.target}&output=json"

        try:
            resp = requests.get(url, timeout=15, headers={"User-Agent": "ReconX/0.1"})
            resp.raise_for_status()
            entries = resp.json()
        except requests.exceptions.RequestException as e:
            warn(f"crt.sh request failed: {e}")
            return
        except json.JSONDecodeError:
            warn("crt.sh returned non-JSON response — rate limited?")
            return

        seen_names = set()
        for entry in entries:
            # name_value can have newline-separated multiple names
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower()
                # Skip wildcard entries and out-of-scope domains
                if name.startswith("*"):
                    name = name.lstrip("*.")
                if not name.endswith(self.target) or name in seen_names:
                    continue
                seen_names.add(name)
                self._resolve_and_add(name, source="crt.sh")

        info(f"crt.sh returned [accent]{len(seen_names)}[/accent] unique names to resolve")

    # ── Source: VirusTotal Passive DNS ───────────────────────

    def _run_virustotal(self):
        """Query VirusTotal passive DNS — requires VIRUSTOTAL_API_KEY in .env."""
        api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        if not api_key:
            info("VirusTotal: no API key set in .env — skipping")
            return

        info("Querying VirusTotal passive DNS...")
        url = f"https://www.virustotal.com/api/v3/domains/{self.target}/subdomains"
        headers = {"x-apikey": api_key}

        try:
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 401:
                warn("VirusTotal: invalid API key")
                return
            resp.raise_for_status()
            data = resp.json()
        except requests.exceptions.RequestException as e:
            warn(f"VirusTotal request failed: {e}")
            return

        names = [item["id"] for item in data.get("data", [])]
        info(f"VirusTotal returned [accent]{len(names)}[/accent] subdomains")

        for name in names:
            self._resolve_and_add(name, source="virustotal")

    # ── Source: DNS Brute-Force ───────────────────────────────

    def _run_bruteforce(self):
        """Brute-force subdomains using a wordlist with multithreaded DNS resolution."""
        if not self.wordlist.exists():
            warn(f"Wordlist not found: {self.wordlist}")
            warn("Skipping brute-force. Run:  reconx subs --help  for wordlist options.")
            return

        words = self._load_wordlist()
        info(f"Brute-forcing [accent]{len(words):,}[/accent] entries with [accent]{self.threads}[/accent] threads...")

        sem = threading.Semaphore(self.threads)
        threads = []

        for word in words:
            subdomain = f"{word}.{self.target}"
            t = threading.Thread(
                target=self._brute_worker,
                args=(subdomain, sem),
                daemon=True,
            )
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

    def _brute_worker(self, subdomain: str, sem: threading.Semaphore):
        with sem:
            self._resolve_and_add(subdomain, source="brute")

    # ── DNS Resolution ────────────────────────────────────────

    def _resolve_and_add(self, name: str, source: str):
        """Resolve a subdomain to IP. If resolved, add to results."""
        name = name.lower().strip()
        with self._lock:
            if name in self._seen:
                return
            self._seen.add(name)

        ip, cname = self._resolve_dns(name)

        if not ip:
            return  # Unresolvable — skip

        sub = Subdomain(
            name=name,
            ip=ip,
            source=source,
            status="alive",
            cname=cname,
        )

        with self._lock:
            self.results.append(sub)

        # Live terminal output
        cname_hint = f"  [dim]→ CNAME: {cname}[/dim]" if cname else ""
        found(
            f"[subdomain]{name:<50}[/subdomain]  "
            f"[ip]{ip:<18}[/ip]  "
            f"[dim_text][{source}][/dim_text]{cname_hint}"
        )

        # Fire callback (used by CLI to save on-the-fly)
        if self.on_found:
            self.on_found(sub)

    def _resolve_dns(self, name: str) -> tuple[str, str]:
        """
        Resolve a hostname to its A record IP and optional CNAME.
        Returns (ip, cname). Both empty string if unresolvable.
        """
        ip    = ""
        cname = ""

        # Try CNAME first (useful for subdomain takeover detection later)
        try:
            answers = self.resolver.resolve(name, "CNAME")
            cname = str(answers[0].target).rstrip(".")
        except Exception:
            pass

        # Resolve to IP
        try:
            answers = self.resolver.resolve(name, "A")
            ip = str(answers[0])
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.Timeout, dns.exception.DNSException):
            pass
        except Exception:
            pass

        return ip, cname

    # ── Helpers ───────────────────────────────────────────────

    def _load_wordlist(self) -> list[str]:
        """Load and clean wordlist file."""
        with open(self.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            return [
                line.strip().lower()
                for line in f
                if line.strip() and not line.startswith("#")
            ]

    def _wordlist_size(self) -> int:
        if not self.wordlist.exists():
            return 0
        return sum(1 for _ in open(self.wordlist) if _.strip())
