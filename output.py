"""
ReconX Output Utilities
Handles all terminal output using Rich for beautiful CLI display.
"""

from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
from rich.text import Text
from rich import box
import time

# ── Custom theme ──────────────────────────────────────────────
theme = Theme({
    "success":    "bold bright_green",
    "error":      "bold red",
    "warning":    "bold yellow",
    "info":       "bold cyan",
    "subdomain":  "bright_green",
    "ip":         "cyan",
    "module":     "bold magenta",
    "dim_text":   "dim white",
    "accent":     "bold bright_cyan",
})

console = Console(theme=theme)


def banner():
    """Print the ReconX ASCII banner."""
    art = """
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ 
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ 
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝"""

    console.print(art, style="bold bright_green")
    console.print(
        "  [dim_text]Automated Reconnaissance Framework[/dim_text]  "
        "[dim_text]v0.1.0 — 60-Day Bug Bounty Challenge[/dim_text]\n"
    )


def section_header(title: str, icon: str = "◈"):
    """Print a styled section header."""
    console.print(f"\n[module]{icon} {title.upper()}[/module]")
    console.print("[dim_text]" + "─" * (len(title) + 4) + "[/dim_text]")


def found(msg: str):
    """Print a success/found message."""
    console.print(f"  [success]✓[/success]  {msg}")


def info(msg: str):
    """Print an info message."""
    console.print(f"  [info]→[/info]  {msg}")


def warn(msg: str):
    """Print a warning message."""
    console.print(f"  [warning]⚠[/warning]  {msg}")


def error(msg: str):
    """Print an error message."""
    console.print(f"  [error]✗[/error]  {msg}")


def stat_row(label: str, value: str, color: str = "accent"):
    """Print a key: value stat row."""
    console.print(f"  [dim_text]{label:<20}[/dim_text][{color}]{value}[/{color}]")


def summary_panel(title: str, stats: dict, accent_color: str = "bright_green"):
    """Print a summary panel with stats."""
    lines = []
    for k, v in stats.items():
        lines.append(f"  [dim_text]{k:<22}[/dim_text][{accent_color}]{v}[/{accent_color}]")
    content = "\n".join(lines)
    console.print(Panel(
        content,
        title=f"[bold {accent_color}]{title}[/bold {accent_color}]",
        border_style=accent_color,
        box=box.ROUNDED,
        padding=(1, 2),
    ))
