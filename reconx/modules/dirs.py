"""
ReconX Module: Directory & Endpoint Discovery
Day 4 — 60-Day Bug Bounty Challenge

Discovers hidden directories, files, and API endpoints via
multithreaded HTTP fuzzing with smart false-positive filtering.

Usage:
    from reconx.modules.dirs import DirScanner
    scanner = DirScanner(target="https://example.com", wordlist="wordlists/directories.txt")
    result  = scanner.run()
"""

import threading
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urljoin, urlparse

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from rich.markup import escape
from rich.progress import (
    Progress, SpinnerColumn, BarColumn,
    TextColumn, TimeElapsedColumn, TaskProgressColumn,
)
from rich.table import Table
from rich import box

from reconx.utils.output import (
    console, section_header, info, warn, error, summary_panel,
)

warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# ── Status code styling ───────────────────────────────────────────────
_STATUS_STYLE: dict[int, str] = {
    200: "bold green",
    201: "bold green",
    204: "bold green",
    301: "bold blue",
    302: "bold blue",
    307: "bold blue",
    308: "bold blue",
    401: "bold yellow",
    403: "bold yellow",
    405: "bold yellow",
    500: "bold red",
    502: "bold red",
    503: "bold red",
}

# ── Keywords that flag a path as interesting ──────────────────────────
_INTERESTING = {
    ".git", ".env", ".htaccess", ".htpasswd", ".ssh", "id_rsa",
    "backup", "backups", "bak", ".bak", "dump", "sql",
    "admin", "administrator", "admins", "manage", "panel",
    "config", "configuration", "settings", "database", "db",
    "debug", "phpinfo", "shell", "cmd",
    "upload", "uploads",
    "token", "secret", "credential", "password", "passwd",
    "swagger", "openapi", "graphql",
    "actuator", "server-status", "server-info",
    "wp-config", "xmlrpc",
}

_DEFAULT_WORDLIST = (
    Path(__file__).parent.parent.parent / "wordlists" / "directories.txt"
)

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) "
        "Gecko/20100101 Firefox/120.0"
    ),
    "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection":      "keep-alive",
}


# ── Data models ───────────────────────────────────────────────────────

@dataclass
class DirHit:
    path:        str
    url:         str
    status:      int
    size:        int
    words:       int
    lines:       int
    redirect:    str  = ""
    interesting: bool = False
    content_type:str  = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DirResult:
    target:       str
    base_url:     str        = ""
    timestamp:    str        = ""
    elapsed_sec:  float      = 0.0
    total_tested: int        = 0
    hits:         list       = field(default_factory=list)
    error:        str        = ""

    @property
    def interesting_hits(self) -> list:
        return [h for h in self.hits if h.interesting]

    def to_dict(self) -> dict:
        return {
            "target":        self.target,
            "module":        "dirs",
            "base_url":      self.base_url,
            "timestamp":     self.timestamp,
            "elapsed_sec":   self.elapsed_sec,
            "total_tested":  self.total_tested,
            "total_found":   len(self.hits),
            "total_interesting": len(self.interesting_hits),
            "error":         self.error,
            "hits":          [h.to_dict() for h in self.hits],
        }


# ── Scanner ───────────────────────────────────────────────────────────

class DirScanner:
    """
    Multithreaded directory and file fuzzer with false-positive filtering.

    Args:
        target          : Base URL to fuzz (e.g. "https://example.com")
        wordlist        : Path to wordlist file (uses built-in if omitted)
        extensions      : File extensions to append e.g. ["php", "bak", "txt"]
        threads         : Concurrent request threads (default 40)
        timeout         : Per-request timeout in seconds (default 8)
        status_codes    : HTTP status codes to report (default: common useful set)
        follow_redirects: Follow redirects for final response (default False —
                          we want to see 301/302 separately)
        on_found        : Optional callback called with each DirHit as found
    """

    def __init__(
        self,
        target:           str,
        wordlist:         Optional[str]         = None,
        extensions:       Optional[list[str]]   = None,
        threads:          int                   = 40,
        timeout:          int                   = 8,
        status_codes:     Optional[set[int]]    = None,
        follow_redirects: bool                  = False,
        on_found:         Optional[Callable]    = None,
    ):
        self.target           = self._normalise(target)
        self.wordlist         = Path(wordlist) if wordlist else _DEFAULT_WORDLIST
        self.extensions       = extensions or []
        self.threads          = threads
        self.timeout          = timeout
        self.status_codes     = status_codes or {200,201,204,301,302,307,308,401,403,405,500}
        self.follow_redirects = follow_redirects
        self.on_found         = on_found

        self._hits:   list[DirHit] = []
        self._lock    = threading.Lock()
        self._session = self._make_session()

    # ── Public ────────────────────────────────────────────────

    def run(self) -> DirResult:
        section_header("Directory & Endpoint Discovery", "📂")
        info(f"Target     : [accent]{self.target}[/accent]")

        # Load wordlist
        words = self._load_wordlist()
        if not words:
            error(f"Wordlist empty or not found: {self.wordlist}")
            return DirResult(target=self.target,
                             timestamp=datetime.utcnow().isoformat() + "Z",
                             error="wordlist not found")

        # Build full path list (words + extensions)
        paths = self._build_paths(words)
        info(f"Wordlist   : [accent]{len(words):,}[/accent] words → "
             f"[accent]{len(paths):,}[/accent] paths "
             f"(exts: {self.extensions or ['none']})")
        info(f"Threads    : [accent]{self.threads}[/accent]")
        info(f"Codes      : [accent]{sorted(self.status_codes)}[/accent]")

        # Baseline — learn what a 404 looks like on this target
        baseline = self._get_baseline()
        if baseline:
            info(f"Baseline   : [accent]{baseline['status']}[/accent]  "
                 f"size=[accent]{baseline['size']}[/accent] bytes  "
                 f"(soft-404 filter active)")
        else:
            warn("Baseline request failed — soft-404 filter disabled")

        start = time.time()
        console.print()

        # ── Scan with progress bar ────────────────────────────
        with Progress(
            SpinnerColumn(style="green"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=30, style="green", complete_style="bright_green"),
            TaskProgressColumn(),
            TextColumn("[dim]{task.fields[found]} found[/dim]"),
            TimeElapsedColumn(),
            console=console,
            refresh_per_second=8,
        ) as prog:
            task = prog.add_task(
                f"Fuzzing {self.target}",
                total=len(paths),
                found=0,
            )

            with ThreadPoolExecutor(max_workers=self.threads) as pool:
                futures = {
                    pool.submit(self._probe, path, baseline): path
                    for path in paths
                }
                for future in as_completed(futures):
                    hit = future.result()
                    prog.advance(task, 1)
                    if hit:
                        with self._lock:
                            self._hits.append(hit)
                            prog.update(task, found=len(self._hits))
                        self._print_hit(hit)
                        if self.on_found:
                            self.on_found(hit)

        elapsed = round(time.time() - start, 2)

        # Sort: interesting first, then by status code
        self._hits.sort(key=lambda h: (0 if h.interesting else 1, h.status, h.path))

        result = DirResult(
            target       = self.target,
            base_url     = self.target,
            timestamp    = datetime.utcnow().isoformat() + "Z",
            elapsed_sec  = elapsed,
            total_tested = len(paths),
            hits         = self._hits,
        )

        self._display_summary(result)
        return result

    # ── Baseline ─────────────────────────────────────────────

    def _get_baseline(self) -> Optional[dict]:
        """Probe a random path to fingerprint what a 404 looks like here."""
        probe = urljoin(self.target, "/reconx_fp_probe_does_not_exist_xyz123abc")
        try:
            r = self._session.get(probe, timeout=self.timeout, allow_redirects=False)
            return {
                "status": r.status_code,
                "size":   len(r.content),
                "words":  len(r.text.split()),
            }
        except Exception:
            return None

    # ── Probe ─────────────────────────────────────────────────

    def _probe(self, path: str, baseline: Optional[dict]) -> Optional[DirHit]:
        """Make one HTTP request, apply filters, return DirHit or None."""
        url = urljoin(self.target, path)
        try:
            r = self._session.get(url, timeout=self.timeout, allow_redirects=False)
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except Exception:
            return None

        # Status filter
        if r.status_code not in self.status_codes:
            return None

        size  = len(r.content)
        words = len(r.text.split())
        lines = r.text.count("\n")

        # Soft-404 filter — skip if response matches baseline exactly
        if baseline and self._is_baseline(r.status_code, size, baseline):
            return None

        # Redirect location
        redirect = ""
        if r.status_code in (301, 302, 307, 308):
            redirect = r.headers.get("Location", "")

        ct = r.headers.get("Content-Type", "").split(";")[0].strip()

        return DirHit(
            path         = f"/{path.lstrip('/')}",
            url          = url,
            status       = r.status_code,
            size         = size,
            words        = words,
            lines        = lines,
            redirect     = redirect,
            interesting  = _is_interesting(path),
            content_type = ct,
        )

    @staticmethod
    def _is_baseline(status: int, size: int, baseline: dict) -> bool:
        """True if this response looks like the baseline 404."""
        return (
            status == baseline["status"]
            and abs(size - baseline["size"]) <= 50
        )

    # ── Display ───────────────────────────────────────────────

    def _print_hit(self, hit: DirHit):
        """Print a single hit live as it's found."""
        sc    = _STATUS_STYLE.get(hit.status, "white")
        flag  = " [bold yellow]⚑[/bold yellow]" if hit.interesting else ""
        redir = f"  [dim]→ {escape(hit.redirect)}[/dim]" if hit.redirect else ""
        console.print(
            f"  [{sc}]{hit.status}[/{sc}]"
            f"  [dim]{hit.size:>7} B[/dim]"
            f"  [bright_white]{escape(hit.path)}[/bright_white]"
            f"{redir}{flag}"
        )

    def _display_summary(self, result: DirResult):
        if not result.hits:
            warn("No paths found. Try a larger wordlist or different extensions.")
            return

        # Full results table
        console.print()
        table = Table(
            show_header  = True,
            header_style = "bold cyan",
            box          = box.SIMPLE_HEAD,
            pad_edge     = False,
            show_edge    = False,
        )
        table.add_column("STATUS", width=8)
        table.add_column("SIZE",   width=9,  style="dim white")
        table.add_column("WORDS",  width=7,  style="dim white")
        table.add_column("LINES",  width=7,  style="dim white")
        table.add_column("PATH",             min_width=38)
        table.add_column("TYPE",             style="dim white", width=20)

        for h in result.hits:
            sc   = _STATUS_STYLE.get(h.status, "white")
            flag = " [bold yellow]⚑[/bold yellow]" if h.interesting else ""
            path_cell = escape(h.path) + flag
            if h.redirect:
                path_cell += f"  [dim]→ {escape(h.redirect)}[/dim]"
            table.add_row(
                f"[{sc}]{h.status}[/{sc}]",
                str(h.size),
                str(h.words),
                str(h.lines),
                path_cell,
                h.content_type,
            )

        console.print(table)

        # Interesting findings callout
        if result.interesting_hits:
            console.print("\n  [bold yellow]⚑ INTERESTING FINDINGS:[/bold yellow]")
            for h in result.interesting_hits:
                sc = _STATUS_STYLE.get(h.status, "white")
                console.print(
                    f"    [{sc}]{h.status}[/{sc}]  "
                    f"[bold white]{escape(h.path)}[/bold white]  "
                    f"[dim]{h.size} bytes[/dim]"
                )

        summary_panel("Directory Discovery Complete", {
            "Target":       result.target,
            "Tested":       f"{result.total_tested:,} paths",
            "Found":        str(len(result.hits)),
            "Interesting":  str(len(result.interesting_hits)),
            "Time":         f"{result.elapsed_sec:.1f}s",
            "Speed":        f"{result.total_tested / max(result.elapsed_sec, 0.1):.0f} req/s",
        }, accent_color="bright_cyan")

    # ── Helpers ───────────────────────────────────────────────

    def _make_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update(_HEADERS)
        s.verify = False
        return s

    def _load_wordlist(self) -> list[str]:
        if not self.wordlist.exists():
            return []
        with open(self.wordlist, encoding="utf-8", errors="ignore") as f:
            return [
                line.strip().lstrip("/")
                for line in f
                if line.strip() and not line.startswith("#")
            ]

    def _build_paths(self, words: list[str]) -> list[str]:
        """Expand word list with optional file extensions."""
        paths = list(words)
        for word in words:
            # Skip words that already have an extension
            if "." in word.split("/")[-1]:
                continue
            for ext in self.extensions:
                paths.append(f"{word}.{ext.lstrip('.')}")
        return paths

    @staticmethod
    def _normalise(target: str) -> str:
        t = target.strip().rstrip("/")
        if not t.startswith(("http://", "https://")):
            t = f"https://{t}"
        # Ensure trailing slash for urljoin to work correctly
        if not urlparse(t).path:
            t += "/"
        return t


# ── Helpers ───────────────────────────────────────────────────────────

def _is_interesting(path: str) -> bool:
    pl = path.lower()
    return any(kw in pl for kw in _INTERESTING)