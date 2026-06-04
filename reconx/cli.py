"""
ReconX CLI — Entry Point

Day 1: `reconx subs`    — Subdomain enumeration       done
Day 2: `reconx ports`   — Port scanning               done
Day 3: `reconx tech`    — Tech fingerprinting         done
Day 4: `reconx dirs`    — Directory discovery         done
Day 5: `reconx report`  — Report generation           (coming)
Day 6: `reconx notify`  — Notifications               (coming)
Day 7: `reconx full`    — Full pipeline               (coming)
"""

import json
import time
from pathlib import Path
from datetime import datetime

import click

from reconx.utils.output import console, banner, info, warn, error


# ── CLI group ─────────────────────────────────────────────────────────

@click.group()
@click.version_option("0.2.0", prog_name="ReconX")
def cli():
    """
    \b
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝

    Automated Reconnaissance Framework for Bug Bounty Hunting
    """
    pass


# ── Day 1: `reconx subs` ─────────────────────────────────────────────

@cli.command("subs")
@click.option("-t", "--target",   required=True, help="Target domain (e.g. example.com)")
@click.option("-w", "--wordlist", default=None,  help="Custom wordlist path")
@click.option("--threads",        default=50,    show_default=True, help="DNS brute-force threads")
@click.option("--timeout",        default=2.0,   show_default=True, help="DNS query timeout (seconds)")
@click.option("--sources",        default="brute,crt,virustotal", show_default=True,
              help="Sources: brute, crt, virustotal")
@click.option("-o", "--output",   default=None,  help="Output JSON file (auto-named if omitted)")
@click.option("--no-banner",      is_flag=True,  help="Skip the ASCII banner")
def subs(target, wordlist, threads, timeout, sources, output, no_banner):
    """
    \b
    Enumerate subdomains using passive CT logs and active DNS brute-force.

    \b
    Examples:
      reconx subs -t example.com
      reconx subs -t example.com --sources crt
      reconx subs -t example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
      reconx subs -t example.com -o results/subs.json
    """
    if not no_banner:
        banner()

    source_list = [s.strip() for s in sources.split(",") if s.strip()]
    invalid = set(source_list) - {"brute", "crt", "virustotal"}
    if invalid:
        error(f"Unknown sources: {', '.join(invalid)}. Valid: brute, crt, virustotal")
        raise click.Abort()

    output_path  = _resolve_output_path(output, target, "subs")
    found_buffer = []

    def on_found(sub):
        found_buffer.append(sub.to_dict())
        _save_json(output_path, {
            "target":    target,
            "module":    "subdomains",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "count":     len(found_buffer),
            "results":   found_buffer,
        })

    from reconx.modules.subdomains import SubdomainEnumerator
    enumerator = SubdomainEnumerator(
        target   = target,
        wordlist = wordlist,
        threads  = threads,
        timeout  = timeout,
        sources  = source_list,
        on_found = on_found,
    )

    start   = time.time()
    results = enumerator.run()

    _save_json(output_path, {
        "target":      target,
        "module":      "subdomains",
        "timestamp":   datetime.utcnow().isoformat() + "Z",
        "elapsed_sec": round(time.time() - start, 2),
        "count":       len(results),
        "results":     [r.to_dict() for r in results],
    })
    info(f"Results saved → [accent]{output_path}[/accent]")

    unique_ips = {r.ip for r in results if r.ip}
    if unique_ips:
        console.print(f"\n  [dim]Unique IPs:[/dim] [accent]{len(unique_ips)}[/accent]")
        for ip in sorted(unique_ips):
            console.print(f"    [cyan]{ip}[/cyan]")


# ── Day 2: `reconx ports` ────────────────────────────────────────────

@cli.command("ports")
@click.option("-t", "--target",     required=True,  help="Target IP or hostname")
@click.option("--top",              default=1000,   show_default=True,
              help="Scan top N common ports")
@click.option("-p", "--ports",      default="",
              help="Specific ports: '22,80,443' or '1-1024' (overrides --top)")
@click.option("--timeout",          default=300,    show_default=True,
              help="Max scan time in seconds")
@click.option("--skip-ping",        is_flag=True,
              help="Skip host discovery (-Pn). Use when ICMP is blocked.")
@click.option("--all-ports",        is_flag=True,
              help="Show filtered/closed ports too (default: open only)")
@click.option("-o", "--output",     default=None,
              help="Output JSON file (auto-named if omitted)")
@click.option("--no-banner",        is_flag=True,   help="Skip the ASCII banner")
def ports(target, top, ports, timeout, skip_ping, all_ports, output, no_banner):
    """
    \b
    Scan open ports and detect running services with risk ratings.
    Requires nmap: sudo pacman -S nmap

    \b
    Examples:
      reconx ports -t 192.168.1.1
      reconx ports -t example.com --top 100
      reconx ports -t 10.0.0.1 -p 22,80,443,3306,6379
      reconx ports -t example.com --skip-ping --top 200
      reconx ports -t 10.0.0.1 -p 1-65535 --timeout 600
    """
    if not no_banner:
        banner()

    from reconx.modules.ports import PortScanner

    scanner = PortScanner(
        target    = target,
        top       = top,
        ports     = ports,
        timeout   = timeout,
        skip_ping = skip_ping,
        open_only = not all_ports,
    )

    result      = scanner.run()
    output_path = _resolve_output_path(output, target, "ports")
    _save_json(output_path, result.to_dict())
    info(f"Results saved → [accent]{output_path}[/accent]")

    if result.error:
        raise click.ClickException(result.error)


# ── Day 3: `reconx tech` ─────────────────────────────────────────────

@cli.command("tech")
@click.option("-t", "--target",   required=True, help="Target URL or domain (e.g. example.com)")
@click.option("--timeout",        default=12,    show_default=True, help="HTTP request timeout (seconds)")
@click.option("--no-redirect",    is_flag=True,  help="Don't follow HTTP redirects")
@click.option("-o", "--output",   default=None,  help="Output JSON file (auto-named if omitted)")
@click.option("--no-banner",      is_flag=True,  help="Skip the ASCII banner")
def tech(target, timeout, no_redirect, output, no_banner):
    """
    \b
    Fingerprint web technology stack from HTTP headers and HTML body.
    Detects: server, language, CMS, JS framework, CDN, WAF, security headers.

    \b
    Examples:
      reconx tech -t example.com
      reconx tech -t https://shop.example.com
      reconx tech -t example.com -o results/tech.json
    """
    if not no_banner:
        banner()

    from reconx.modules.tech import TechFingerprinter

    fp     = TechFingerprinter(
        target           = target,
        timeout          = timeout,
        follow_redirects = not no_redirect,
    )
    result      = fp.run()
    output_path = _resolve_output_path(output, target, "tech")
    _save_json(output_path, result.to_dict())
    info(f"Results saved → [accent]{output_path}[/accent]")

    if result.error:
        raise click.ClickException(result.error)


# ── Day 4 placeholder ─────────────────────────────────────────────────

@cli.command("dirs")
@click.option("-t", "--target",     required=True,
              help="Target URL (e.g. https://example.com or example.com/api)")
@click.option("-w", "--wordlist",   default=None,
              help="Wordlist path (uses built-in 212-entry list if omitted)")
@click.option("-x", "--extensions", default="",
              help="File extensions to append: php,bak,txt,json")
@click.option("--threads",          default=40,  show_default=True,
              help="Concurrent request threads")
@click.option("--timeout",          default=8,   show_default=True,
              help="Per-request timeout in seconds")
@click.option("--codes",            default="200,201,204,301,302,307,308,401,403,405,500",
              show_default=True, help="HTTP status codes to report (comma-separated)")
@click.option("-o", "--output",     default=None,
              help="Output JSON file (auto-named if omitted)")
@click.option("--no-banner",        is_flag=True, help="Skip the ASCII banner")
def dirs(target, wordlist, extensions, threads, timeout, codes, output, no_banner):
    """
    \b
    Discover hidden directories, files, and API endpoints via HTTP fuzzing.
    Uses built-in wordlist by default. Highlights sensitive findings automatically.

    \b
    Examples:
      reconx dirs -t example.com
      reconx dirs -t https://example.com/api
      reconx dirs -t example.com -x php,bak,txt
      reconx dirs -t example.com -w /usr/share/seclists/Discovery/Web-Content/common.txt
      reconx dirs -t example.com --threads 80 --timeout 5
    """
    if not no_banner:
        banner()

    from reconx.modules.dirs import DirScanner

    try:
        code_set = {int(c.strip()) for c in codes.split(",") if c.strip()}
    except ValueError:
        error("Invalid --codes value. Example: 200,301,403")
        raise click.Abort()

    ext_list = [e.strip() for e in extensions.split(",") if e.strip()]

    def on_found(hit):
        pass   # live save handled by summary write after scan

    scanner = DirScanner(
        target       = target,
        wordlist     = wordlist,
        extensions   = ext_list,
        threads      = threads,
        timeout      = timeout,
        status_codes = code_set,
        on_found     = on_found,
    )

    result      = scanner.run()
    output_path = _resolve_output_path(output, target, "dirs")
    _save_json(output_path, result.to_dict())
    info(f"Results saved → [accent]{output_path}[/accent]")

    if result.error:
        raise click.ClickException(result.error)


# ── Day 5 placeholder ─────────────────────────────────────────────────

@cli.command("report")
@click.option("-t", "--target", required=True)
@click.option("--format", "fmt", default="html",
              type=click.Choice(["html", "json", "md"]), show_default=True)
@click.option("-o", "--output", default=None)
def report(target, fmt, output):
    """[DAY 5] Generate HTML/JSON/Markdown report from scan results."""
    banner()
    console.print("\n  [yellow]⏳ Report generator coming on Day 5![/yellow]\n")


# ── Day 7 placeholder ─────────────────────────────────────────────────

@cli.command("full")
@click.option("-t", "--target",     required=True)
@click.option("-o", "--output-dir", default="output", show_default=True)
def full(target, output_dir):
    """[DAY 7] Full pipeline: subs → ports → tech → dirs → report."""
    banner()
    console.print("\n  [yellow]⏳ Full pipeline coming on Day 7![/yellow]\n")


# ── Shared helpers ────────────────────────────────────────────────────

def _resolve_output_path(output, target: str, module: str) -> Path:
    if output:
        p = Path(output)
    else:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe = target.replace(".", "_").replace("/", "_").replace(":", "_")
        p    = Path("output") / f"{safe}_{module}_{ts}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _save_json(path: Path, data: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    cli()