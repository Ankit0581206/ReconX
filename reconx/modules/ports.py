"""
ReconX Module: Port Scanner
Day 2 — 60-Day Bug Bounty Challenge

Wraps nmap with structured output, risk ratings, and rich terminal display.

Usage:
    from reconx.modules.ports import PortScanner
    scanner = PortScanner(target="192.168.1.1", top=1000)
    result  = scanner.run()
"""

import subprocess
import shutil
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from datetime import datetime

from rich.table import Table
from rich.markup import escape
from rich import box

from reconx.utils.output import (
    console, section_header, info, warn, error, summary_panel
)

# ── Risk table: service name → severity ──────────────────────────────

_RISK: dict[str, str] = {
    # Critical — unauthenticated shell / trivial RCE
    "telnet":         "CRITICAL",
    "rdp":            "CRITICAL",
    "ms-wbt-server":  "CRITICAL",
    "vnc":            "CRITICAL",
    "rexec":          "CRITICAL",
    "rlogin":         "CRITICAL",
    "rsh":            "CRITICAL",
    # High — common attack surface
    "ssh":            "HIGH",
    "ftp":            "HIGH",
    "mysql":          "HIGH",
    "postgresql":     "HIGH",
    "ms-sql-s":       "HIGH",
    "mssql":          "HIGH",
    "mongodb":        "HIGH",
    "redis":          "HIGH",
    "elasticsearch":  "HIGH",
    "oracle-tns":     "HIGH",
    "snmp":           "HIGH",
    "smb":            "HIGH",
    "netbios-ssn":    "HIGH",
    "microsoft-ds":   "HIGH",
    "nfs":            "HIGH",
    "ldap":           "HIGH",
    "ldaps":          "HIGH",
    "docker":         "HIGH",
    "kubernetes":     "HIGH",
    # Medium — context-dependent risk
    "http":           "MEDIUM",
    "http-proxy":     "MEDIUM",
    "http-alt":       "MEDIUM",
    "smtp":           "MEDIUM",
    "pop3":           "MEDIUM",
    "imap":           "MEDIUM",
    "dns":            "MEDIUM",
    "rpcbind":        "MEDIUM",
    "pptp":           "MEDIUM",
    "l2tp":           "MEDIUM",
    "ajp13":          "MEDIUM",
    # Low — encrypted / standard
    "https":          "LOW",
    "smtps":          "LOW",
    "pop3s":          "LOW",
    "imaps":          "LOW",
    "ftps":           "LOW",
    "sftp":           "LOW",
}

_RISK_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "INFO":     "dim white",
}


# ── Data models ───────────────────────────────────────────────────────

@dataclass
class Port:
    port:      int
    protocol:  str
    state:     str
    service:   str  = ""
    product:   str  = ""
    version:   str  = ""
    extrainfo: str  = ""
    tunnel:    str  = ""
    risk:      str  = "INFO"

    @property
    def display_version(self) -> str:
        parts = [p for p in [self.product, self.version, self.extrainfo] if p]
        return " ".join(parts) if parts else self.service

    def to_dict(self) -> dict:
        d = asdict(self)
        d["display_version"] = self.display_version
        return d


@dataclass
class ScanResult:
    target:       str
    ip:           str   = ""
    hostname:     str   = ""
    status:       str   = "unknown"
    ports:        list  = field(default_factory=list)
    open_count:   int   = 0
    elapsed_sec:  float = 0.0
    nmap_version: str   = ""
    command_line: str   = ""
    timestamp:    str   = ""
    error:        str   = ""

    def to_dict(self) -> dict:
        return {
            "target":       self.target,
            "module":       "ports",
            "timestamp":    self.timestamp,
            "ip":           self.ip,
            "hostname":     self.hostname,
            "status":       self.status,
            "open_count":   self.open_count,
            "elapsed_sec":  self.elapsed_sec,
            "nmap_version": self.nmap_version,
            "command_line": self.command_line,
            "error":        self.error,
            "ports":        [p.to_dict() for p in self.ports],
        }


# ── Scanner ───────────────────────────────────────────────────────────

class PortScanner:
    """
    Nmap wrapper with structured output and risk ratings.

    Args:
        target      : IP address or hostname to scan
        top         : Scan top N most common ports (default 1000)
        ports       : Specific ports e.g. "22,80,443" or "1-65535"
                      Overrides `top` when set.
        timeout     : Max seconds for entire scan (default 300)
        skip_ping   : Pass -Pn (treat host as up — use when ICMP is blocked)
        open_only   : Only include open ports in results (default True)
    """

    def __init__(
        self,
        target:    str,
        top:       int  = 1000,
        ports:     str  = "",
        timeout:   int  = 300,
        skip_ping: bool = False,
        open_only: bool = True,
    ):
        self.target    = target.strip()
        self.top       = top
        self.ports     = ports.strip()
        self.timeout   = timeout
        self.skip_ping = skip_ping
        self.open_only = open_only

    # ── Public ────────────────────────────────────────────────

    def run(self) -> ScanResult:
        """Run the scan and return a ScanResult."""
        section_header("Port Scanner", "🔍")
        info(f"Target     : [accent]{self.target}[/accent]")

        # Verify nmap is available
        nmap_ok, nmap_ver = self._check_nmap()
        if not nmap_ok:
            error("nmap not found.")
            error("Install: [accent]sudo pacman -S nmap[/accent]   (Garuda/Arch)")
            error("         [accent]sudo apt install nmap[/accent]  (Debian/Ubuntu)")
            return ScanResult(
                target=self.target,
                timestamp=datetime.utcnow().isoformat() + "Z",
                error="nmap not installed",
            )

        info(f"Nmap       : [accent]{nmap_ver}[/accent]")

        if self.ports:
            info(f"Ports      : [accent]{self.ports}[/accent]")
        else:
            info(f"Top ports  : [accent]{self.top}[/accent]")

        if self.skip_ping:
            info("Ping check : [accent]disabled (-Pn)[/accent]")

        cmd   = self._build_command()
        start = time.time()

        console.print()
        info(f"Running: [dim]{' '.join(cmd)}[/dim]")
        info("This may take a minute — nmap is probing services...\n")

        # Execute nmap
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            elapsed = round(time.time() - start, 2)
            error(f"Scan timed out after {self.timeout}s.")
            warn("Try:  --skip-ping   to skip host discovery")
            warn("      --top 100    to scan fewer ports")
            return ScanResult(
                target=self.target,
                elapsed_sec=elapsed,
                timestamp=datetime.utcnow().isoformat() + "Z",
                error=f"timeout after {self.timeout}s",
            )
        except FileNotFoundError:
            return ScanResult(
                target=self.target,
                timestamp=datetime.utcnow().isoformat() + "Z",
                error="nmap executable not found in PATH",
            )
        except Exception as e:
            return ScanResult(
                target=self.target,
                timestamp=datetime.utcnow().isoformat() + "Z",
                error=str(e),
            )

        elapsed = round(time.time() - start, 2)

        # nmap writes errors to stderr but still exits 0
        if not proc.stdout.strip():
            msg = proc.stderr.strip() or f"nmap produced no output (exit {proc.returncode})"
            error(msg)
            return ScanResult(
                target=self.target,
                elapsed_sec=elapsed,
                timestamp=datetime.utcnow().isoformat() + "Z",
                error=msg,
            )

        result = self._parse_xml(
            proc.stdout, elapsed, nmap_ver, " ".join(cmd)
        )
        self._display(result)
        return result

    # ── Nmap helpers ──────────────────────────────────────────

    def _check_nmap(self) -> tuple[bool, str]:
        if not shutil.which("nmap"):
            return False, ""
        try:
            r = subprocess.run(
                ["nmap", "--version"],
                capture_output=True, text=True, timeout=5
            )
            ver = r.stdout.splitlines()[0] if r.stdout else "nmap (unknown version)"
            return True, ver
        except Exception:
            return False, ""

    def _build_command(self) -> list[str]:
        cmd = ["nmap", "-sV", "-T4", "-oX", "-"]
        if self.skip_ping:
            cmd.append("-Pn")
        if self.ports:
            cmd.extend(["-p", self.ports])
        else:
            cmd.extend(["--top-ports", str(self.top)])
        cmd.append(self.target)
        return cmd

    # ── XML parser ────────────────────────────────────────────

    def _parse_xml(
        self, xml_str: str, elapsed: float, nmap_ver: str, cmd: str
    ) -> ScanResult:
        result = ScanResult(
            target       = self.target,
            elapsed_sec  = elapsed,
            nmap_version = nmap_ver,
            command_line = cmd,
            timestamp    = datetime.utcnow().isoformat() + "Z",
        )

        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as e:
            result.error = f"XML parse error: {e}"
            return result

        host_el = root.find("host")
        if host_el is None:
            result.error = "No host in nmap output — target may be unreachable."
            return result

        # Status
        status_el = host_el.find("status")
        if status_el is not None:
            result.status = status_el.get("state", "unknown")

        # IP address
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") == "ipv4":
                result.ip = addr_el.get("addr", "")
                break

        # Reverse DNS hostname
        for hn in host_el.findall("hostnames/hostname"):
            if hn.get("type") == "PTR":
                result.hostname = hn.get("name", "")
                break

        # Parse ports
        ports: list[Port] = []
        for port_el in host_el.findall("ports/port"):
            state_el   = port_el.find("state")
            service_el = port_el.find("service")

            state = state_el.get("state", "") if state_el is not None else ""
            if self.open_only and state != "open":
                continue

            svc      = ""
            product  = ""
            version  = ""
            extinfo  = ""
            tunnel   = ""

            if service_el is not None:
                svc     = service_el.get("name",      "")
                product = service_el.get("product",   "")
                version = service_el.get("version",   "")
                extinfo = service_el.get("extrainfo", "")
                tunnel  = service_el.get("tunnel",    "")

            # SSL-wrapped HTTP is really HTTPS
            if tunnel == "ssl" and svc == "http":
                svc = "https"

            risk = _RISK.get(svc, "INFO")

            ports.append(Port(
                port      = int(port_el.get("portid", 0)),
                protocol  = port_el.get("protocol", "tcp"),
                state     = state,
                service   = svc,
                product   = product,
                version   = version,
                extrainfo = extinfo,
                tunnel    = tunnel,
                risk      = risk,
            ))

        # Open first, then by port number
        ports.sort(key=lambda p: (0 if p.state == "open" else 1, p.port))
        result.ports      = ports
        result.open_count = sum(1 for p in ports if p.state == "open")
        return result

    # ── Rich display ──────────────────────────────────────────

    def _display(self, result: ScanResult):
        if result.error:
            error(result.error)
            return

        if result.status != "up":
            warn(f"Host reported as [yellow]{result.status}[/yellow] — results may be incomplete.")

        if not result.ports:
            warn("No open ports found in scanned range.")
            warn(f"Host status: {result.status}")
            return

        table = Table(
            show_header  = True,
            header_style = "bold cyan",
            box          = box.SIMPLE_HEAD,
            pad_edge     = False,
            show_edge    = False,
        )
        table.add_column("PORT",    style="bold white",  width=8)
        table.add_column("PROTO",   style="dim white",   width=6)
        table.add_column("STATE",   width=10)
        table.add_column("SERVICE", style="cyan",        width=14)
        table.add_column("VERSION / BANNER",             min_width=28)
        table.add_column("RISK",                         width=10)

        for p in result.ports:
            rc = _RISK_COLOR[p.risk]

            state_str = (
                "[bold green]open[/bold green]"     if p.state == "open"     else
                "[yellow]filtered[/yellow]"         if p.state == "filtered" else
                "[dim]closed[/dim]"
            )

            table.add_row(
                str(p.port),
                p.protocol,
                state_str,
                escape(p.service),
                escape(p.display_version) or "[dim]—[/dim]",
                f"[{rc}]{p.risk}[/{rc}]",
            )

        console.print(table)

        summary_panel("Port Scan Complete", {
            "Target":      result.target,
            "IP":          result.ip or "—",
            "Hostname":    result.hostname or "—",
            "Status":      result.status,
            "Open ports":  str(result.open_count),
            "Time":        f"{result.elapsed_sec:.1f}s",
        }, accent_color="bright_cyan")