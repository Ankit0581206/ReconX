"""
ReconX Module: Subdomain Enumerator
Day 1 — 60-Day Bug Bounty Challenge

Techniques used:
  1. DNS brute-force         — wordlist entries resolved via DNS
  2. Certificate transparency — HackerTarget + crt.sh + BufferOver
  3. VirusTotal passive DNS  — queries VT if API key is set

Usage:
    from reconx.modules.subdomains import SubdomainEnumerator
    e = SubdomainEnumerator(target="vulnweb.com")
    results = e.run()
"""

import os
import time
import json
import threading
from pathlib import Path
from typing import Callable
from dataclasses import dataclass, field, asdict

import dns.resolver
import requests
from dotenv import load_dotenv

from reconx.utils.output import console, section_header, found, info, warn, error

load_dotenv()


# Data Model


@dataclass
class Subdomain:
    name:   str
    ip:     str  = ""
    source: str  = ""
    status: str  = "alive"
    cname:  str  = ""
    extra:  dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)



# SubdomainEnumerator


class SubdomainEnumerator:
    DEFAULT_WORDLIST = Path(__file__).parent.parent.parent / "wordlists" / "subdomains.txt"

    def __init__(
        self,
        target:   str,
        wordlist: str | None            = None,
        threads:  int                   = 50,
        timeout:  float                 = 2.0,
        sources:  list[str] | None      = None,
        on_found: Callable | None       = None,
    ):
        self.target   = target.lower().strip().removeprefix("http://").removeprefix("https://").rstrip("/")
        self.wordlist = Path(wordlist) if wordlist else self.DEFAULT_WORDLIST
        self.threads  = threads
        self.timeout  = timeout
        self.sources  = sources or ["brute", "crt", "virustotal"]
        self.on_found = on_found

        self.results: list[Subdomain] = []
        self._seen:   set[str]        = set()
        self._lock    = threading.Lock()

        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout     = timeout
        self.resolver.lifetime    = timeout
        self.resolver.nameservers = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]

    # ── Public ───────────────────────────────────────────────

    def run(self) -> list[Subdomain]:
        section_header("Subdomain Enumeration", "🔭")
        info(f"Target     : [accent]{self.target}[/accent]")
        info(f"Sources    : [accent]{', '.join(self.sources)}[/accent]")
        info(f"Threads    : [accent]{self.threads}[/accent]")

        # Warn if target looks like a subdomain
        parts = self.target.split(".")
        if len(parts) > 2:
            warn(f"[yellow]{self.target}[/yellow] looks like a subdomain.")
            warn(f"Did you mean: [accent]{'.'.join(parts[-2:])}[/accent] ?")

        start = time.time()

        if "crt"        in self.sources: self._run_ct_logs()
        if "virustotal" in self.sources: self._run_virustotal()
        if "brute"      in self.sources: self._run_bruteforce()

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

    # ── CT Logs (3 sources with fallback) ────────────────────

    def _run_ct_logs(self):
        """Query Certificate Transparency logs using 3 sources as fallbacks."""
        info("Querying Certificate Transparency logs...")
        names: set[str] = set()

        # ── Source 1: HackerTarget ────────────────────────────
        try:
            resp = requests.get(
                "https://api.hackertarget.com/hostsearch/",
                params={"q": self.target},
                timeout=15,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0)"},
            )
            if resp.status_code == 200 and "error" not in resp.text.lower():
                for line in resp.text.strip().splitlines():
                    host = line.split(",")[0].strip().lower()
                    if host and host.endswith(self.target):
                        names.add(host)
                info(f"  HackerTarget  → [accent]{len(names)}[/accent] names")
            else:
                warn(f"  HackerTarget  → {resp.status_code} / {resp.text[:80]}")
        except requests.exceptions.RequestException as e:
            warn(f"  HackerTarget  → failed: {e}")

        # ── Source 2: crt.sh (skip for huge domains) ─────────
        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            resp = requests.get(
                url,
                timeout=20,
                headers={
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
                    "Accept": "application/json",
                },
            )
            resp.raise_for_status()
            before = len(names)
            for entry in resp.json():
                for n in entry.get("name_value", "").split("\n"):
                    n = n.strip().lower()
                    if n.startswith("*") or not n.endswith(self.target):
                        continue
                    names.add(n)
            info(f"  crt.sh        → [accent]{len(names) - before}[/accent] new names  (total: {len(names)})")
        except requests.exceptions.Timeout:
            warn("  crt.sh        → timed out (domain too large)")
        except requests.exceptions.RequestException as e:
            warn(f"  crt.sh        → failed: {e}")
        except (json.JSONDecodeError, ValueError):
            warn("  crt.sh        → non-JSON response (rate limited?)")

        # ── Source 3: BufferOver ──────────────────────────────
        try:
            resp = requests.get(
                "https://dns.bufferover.run/dns",
                params={"q": f".{self.target}"},
                timeout=10,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if resp.status_code == 200:
                before = len(names)
                data   = resp.json()
                for record in data.get("FDNS_A", []) + data.get("RDNS", []):
                    host = record.split(",")[-1].strip().lower()
                    if host.endswith(self.target):
                        names.add(host)
                info(f"  BufferOver    → [accent]{len(names) - before}[/accent] new names  (total: {len(names)})")
        except Exception:
            pass  # BufferOver goes offline often — silent skip

        if not names:
            warn("All CT sources returned 0 results.")
            warn("Possible reasons: domain has no public certs, all APIs are down,")
            warn("or network is blocking outbound HTTPS to these hosts.")
            warn("Try:  reconx subs -t vulnweb.com --sources brute")
            return

        info(f"Resolving [accent]{len(names)}[/accent] unique CT names...")
        for name in sorted(names):
            self._resolve_and_add(name, source="ct-logs")

    # ── VirusTotal ────────────────────────────────────────────

    def _run_virustotal(self):
        api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        if not api_key:
            info("VirusTotal: no API key in .env — skipping")
            return

        info("Querying VirusTotal passive DNS...")
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{self.target}/subdomains",
                headers={"x-apikey": api_key},
                timeout=15,
            )
            if resp.status_code == 401:
                warn("VirusTotal: invalid API key"); return
            resp.raise_for_status()
            names = [item["id"] for item in resp.json().get("data", [])]
            info(f"VirusTotal returned [accent]{len(names)}[/accent] subdomains")
            for name in names:
                self._resolve_and_add(name, source="virustotal")
        except requests.exceptions.RequestException as e:
            warn(f"VirusTotal failed: {e}")

    # ── DNS Brute-Force ───────────────────────────────────────

    def _run_bruteforce(self):
        if not self.wordlist.exists():
            warn(f"Wordlist not found: {self.wordlist}")
            return

        words = self._load_wordlist()
        info(f"Brute-forcing [accent]{len(words):,}[/accent] entries with [accent]{self.threads}[/accent] threads...")

        sem     = threading.Semaphore(self.threads)
        threads = []
        for word in words:
            t = threading.Thread(
                target=self._brute_worker,
                args=(f"{word}.{self.target}", sem),
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
        name = name.lower().strip()
        with self._lock:
            if name in self._seen:
                return
            self._seen.add(name)

        ip, cname = self._resolve_dns(name)
        if not ip:
            return

        sub = Subdomain(name=name, ip=ip, source=source, cname=cname)
        with self._lock:
            self.results.append(sub)

        cname_hint = f"  [dim]→ {cname}[/dim]" if cname else ""
        from rich.markup import escape
        found(
            f"[subdomain]{escape(name):<50}[/subdomain]  "
            f"[ip]{ip:<18}[/ip]  "
            f"[dim_text][{source}][/dim_text]{cname_hint}"
        )
        if self.on_found:
            self.on_found(sub)

    def _resolve_dns(self, name: str) -> tuple[str, str]:
        ip = cname = ""
        try:
            answers = self.resolver.resolve(name, "CNAME")
            cname   = str(answers[0].target).rstrip(".")
        except Exception:
            pass
        try:
            answers = self.resolver.resolve(name, "A")
            ip      = str(answers[0])
        except Exception:
            pass
        return ip, cname

    # ── Helpers ───────────────────────────────────────────────

    def _load_wordlist(self) -> list[str]:
        with open(self.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            return [l.strip().lower() for l in f if l.strip() and not l.startswith("#")]

    def _wordlist_size(self) -> int:
        if not self.wordlist.exists():
            return 0
        return sum(1 for _ in open(self.wordlist) if _.strip())