"""
ReconX CLI — Entry Point
Grows one command per day over the 60-day challenge.

Day 1: `reconx subs`    — Subdomain enumeration
Day 2: `reconx ports`   — Port scanning          (coming)
Day 3: `reconx tech`    — Tech fingerprinting     (coming)
Day 4: `reconx dirs`    — Directory discovery     (coming)
Day 5: `reconx report`  — Report generation       (coming)
Day 6: `reconx notify`  — Notifications           (coming)
Day 7: `reconx full`    — Full pipeline           (coming)
"""

import json
import time
from pathlib import Path
from datetime import datetime

import click
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from reconx.utils.output import console, banner, info, warn, error


# ── CLI group ────────────────────────────────────────────────

@click.group()
@click.version_option("0.1.0", prog_name="ReconX")
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


# ── Day 1: `reconx subs` ─────────────────────────────────────

@cli.command("subs")
@click.option("-t", "--target",   required=True, help="Target domain (e.g. example.com)")
@click.option("-w", "--wordlist", default=None,  help="Custom wordlist path")
@click.option("--threads",        default=50,    show_default=True, help="DNS brute-force thread count")
@click.option("--timeout",        default=2.0,   show_default=True, help="DNS query timeout in seconds")
@click.option("--sources",        default="brute,crt,virustotal", show_default=True,
              help="Comma-separated sources: brute,crt,virustotal")
@click.option("-o", "--output",   default=None,  help="Output file (JSON). Auto-named if not set.")
@click.option("--no-banner",      is_flag=True,  help="Skip the banner")
def subs(target, wordlist, threads, timeout, sources, output, no_banner):
    """
    \b
    Enumerate subdomains using multiple passive and active sources.

    \b
    Examples:
      reconx subs -t example.com
      reconx subs -t example.com --sources crt,virustotal
      reconx subs -t example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
      reconx subs -t example.com -o results/example_subs.json
    """
    if not no_banner:
        banner()

    # Parse sources
    source_list = [s.strip() for s in sources.split(",") if s.strip()]
    valid_sources = {"brute", "crt", "virustotal"}
    invalid = set(source_list) - valid_sources
    if invalid:
        error(f"Unknown sources: {', '.join(invalid)}. Valid: brute, crt, virustotal")
        raise click.Abort()

    # Determine output path
    output_path = _resolve_output_path(output, target, "subs")

    # Live save callback — writes each found subdomain immediately to JSON
    found_buffer = []

    def on_found(sub):
        found_buffer.append(sub.to_dict())
        _save_json(output_path, {
            "target":     target,
            "module":     "subdomains",
            "timestamp":  datetime.utcnow().isoformat() + "Z",
            "count":      len(found_buffer),
            "results":    found_buffer,
        })

    # Run enumerator
    from reconx.modules.subdomains import SubdomainEnumerator

    enumerator = SubdomainEnumerator(
        target   = target,
        wordlist = wordlist,
        threads  = threads,
        timeout  = timeout,
        sources  = source_list,
        on_found = on_found,
    )

    start = time.time()
    results = enumerator.run()

    # Final save
    final_data = {
        "target":       target,
        "module":       "subdomains",
        "timestamp":    datetime.utcnow().isoformat() + "Z",
        "elapsed_sec":  round(time.time() - start, 2),
        "count":        len(results),
        "results":      [r.to_dict() for r in results],
    }
    _save_json(output_path, final_data)
    info(f"Results saved → [accent]{output_path}[/accent]")

    # Print unique IPs
    unique_ips = {r.ip for r in results if r.ip}
    if unique_ips:
        console.print(f"\n  [dim]Unique IPs:[/dim] [accent]{len(unique_ips)}[/accent]")
        for ip in sorted(unique_ips):
            console.print(f"    [cyan]{ip}[/cyan]")


# ── Day 2 placeholder: `reconx ports` ────────────────────────

@cli.command("ports")
@click.option("-t", "--target", required=True, help="Target IP or hostname")
@click.option("--top", default=1000, show_default=True, help="Scan top N ports")
@click.option("-o", "--output", default=None)
def ports(target, top, output):
    """[DAY 2] Port scan target with service version detection."""
    banner()
    console.print("\n  [yellow]⏳ Port scanner coming on Day 2![/yellow]")
    console.print("  [dim]This command will wrap Nmap with rich output and JSON export.[/dim]\n")


# ── Day 3 placeholder: `reconx tech` ─────────────────────────

@cli.command("tech")
@click.option("-t", "--target", required=True, help="Target URL")
@click.option("-o", "--output", default=None)
def tech(target, output):
    """[DAY 3] Fingerprint technology stack (CMS, server, WAF, CDN)."""
    banner()
    console.print("\n  [yellow]⏳ Tech fingerprinter coming on Day 3![/yellow]\n")


# ── Day 4 placeholder: `reconx dirs` ─────────────────────────

@cli.command("dirs")
@click.option("-t", "--target", required=True, help="Target URL")
@click.option("-w", "--wordlist", default=None)
@click.option("-o", "--output", default=None)
def dirs(target, wordlist, output):
    """[DAY 4] Discover directories and endpoints (FFUF wrapper)."""
    banner()
    console.print("\n  [yellow]⏳ Directory discovery coming on Day 4![/yellow]\n")


# ── Day 5 placeholder: `reconx report` ───────────────────────

@cli.command("report")
@click.option("-t", "--target", required=True, help="Target domain")
@click.option("--format", "fmt", default="html", type=click.Choice(["html", "json", "md"]), show_default=True)
@click.option("-o", "--output", default=None)
def report(target, fmt, output):
    """[DAY 5] Generate HTML/JSON/Markdown report from scan results."""
    banner()
    console.print("\n  [yellow]⏳ Report generator coming on Day 5![/yellow]\n")


# ── Day 7 placeholder: `reconx full` ─────────────────────────

@cli.command("full")
@click.option("-t", "--target", required=True, help="Target domain")
@click.option("-o", "--output-dir", default="output", show_default=True)
def full(target, output_dir):
    """[DAY 7] Run full recon pipeline: subs → ports → tech → dirs → report."""
    banner()
    console.print("\n  [yellow]⏳ Full pipeline coming on Day 7![/yellow]\n")


# ── Helpers ───────────────────────────────────────────────────

def _resolve_output_path(output: str | None, target: str, module: str) -> Path:
    """Auto-generate output path if not specified."""
    if output:
        p = Path(output)
    else:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace(".", "_").replace("/", "_")
        p = Path("output") / f"{safe_target}_{module}_{ts}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _save_json(path: Path, data: dict):
    """Write data as formatted JSON file."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    cli()
