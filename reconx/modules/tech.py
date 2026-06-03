"""
ReconX Module: Technology Fingerprinter
Day 3 — 60-Day Bug Bounty Challenge

Detects web server, language, CMS, JS framework, backend framework,
CDN, WAF, and security header posture — from HTTP headers and HTML body.
No external tools required. Pure Python + requests.

Usage:
    from reconx.modules.tech import TechFingerprinter
    fp     = TechFingerprinter("https://example.com")
    result = fp.run()
"""

import re
import time
import warnings
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from rich.table import Table
from rich.panel import Panel
from rich.markup import escape
from rich.columns import Columns
from rich import box

from reconx.utils.output import (
    console, section_header, info, warn, error, summary_panel
)

warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# ── Fingerprint signatures ────────────────────────────────────────────
# (category, display_name, version_regex|None, match_type, pattern)
# match_type: header_key | header_val | body | cookie

_FP = [
    # Web Servers
    ("server",  "Apache",       r"Apache(?:/(\d+\.\d+\.\d+))?",   "header_val", "server"),
    ("server",  "Nginx",        r"nginx(?:/(\d+\.\d+\.\d+))?",    "header_val", "server"),
    ("server",  "IIS",          r"IIS(?:/(\d+\.\d+))?",           "header_val", "server"),
    ("server",  "LiteSpeed",    r"LiteSpeed",                     "header_val", "server"),
    ("server",  "OpenResty",    r"openresty(?:/(\d+\.\d+))?",     "header_val", "server"),
    ("server",  "Caddy",        r"Caddy",                         "header_val", "server"),
    ("server",  "Gunicorn",     r"gunicorn(?:/(\d+\.\d+))?",      "header_val", "server"),
    ("server",  "Cloudflare",   r"cloudflare",                    "header_val", "server"),
    ("server",  "Tomcat",       r"Apache-Coyote|Tomcat",          "header_val", "server"),

    # Languages
    ("language", "PHP",         r"PHP(?:/(\d+\.\d+(?:\.\d+)?))?", "header_val", "x-powered-by"),
    ("language", "ASP.NET",     r"ASP\.NET",                      "header_val", "x-powered-by"),
    ("language", "ASP.NET",     r"(\d+\.\d+)",                    "header_key", "x-aspnet-version"),
    ("language", "Express.js",  r"Express",                       "header_val", "x-powered-by"),
    ("language", "Next.js",     r"Next\.js",                      "header_val", "x-powered-by"),
    ("language", "Python",      r"Python(?:/(\d+\.\d+))?",        "header_val", "x-powered-by"),

    # CMS
    ("cms", "WordPress",  r"WordPress\s*([\d.]+)?",  "body", r'<meta[^>]+generator[^>]+WordPress\s*([\d.]+)?'),
    ("cms", "WordPress",  None,                      "body", r'/wp-content/'),
    ("cms", "WordPress",  None,                      "body", r'/wp-includes/'),
    ("cms", "WordPress",  None,                      "header_val", "link"),
    ("cms", "WordPress",  None,                      "header_val", "x-generator"),
    ("cms", "Drupal",     r"Drupal\s*([\d.]+)?",    "header_val", "x-generator"),
    ("cms", "Drupal",     None,                      "header_key", "x-drupal-cache"),
    ("cms", "Drupal",     r"Drupal\s*([\d.]+)?",    "body", r'<meta[^>]+Generator[^>]+Drupal\s*([\d.]+)?'),
    ("cms", "Drupal",     None,                      "body", r'sites/default/files'),
    ("cms", "Joomla",     r"Joomla[! ]\s*([\d.]+)?","body", r'<meta[^>]+generator[^>]+Joomla'),
    ("cms", "Joomla",     None,                      "body", r'/media/jui/'),
    ("cms", "Shopify",    None,                      "body", r'cdn\.shopify\.com'),
    ("cms", "Shopify",    None,                      "header_val", "x-shopify-stage"),
    ("cms", "Magento",    None,                      "body", r'Mage\.Cookies|mage/cookies'),
    ("cms", "Ghost",      None,                      "header_key", "x-ghost-cache-status"),
    ("cms", "Wix",        None,                      "body", r'static\.wixstatic\.com'),
    ("cms", "Squarespace",None,                      "body", r'squarespace\.com/'),
    ("cms", "HubSpot",    None,                      "body", r'js\.hsforms\.net|hs-scripts\.com'),
    ("cms", "Webflow",    None,                      "body", r'webflow\.com|Webflow'),

    # JS Frameworks
    ("js_framework", "React",    r"([\d.]+)", "body", r'react(?:\.min)?\.js|data-reactroot'),
    ("js_framework", "Vue.js",   r"([\d.]+)", "body", r'vue(?:\.min)?\.js|data-v-[a-f0-9]'),
    ("js_framework", "Angular",  r"([\d.]+)", "body", r'angular(?:\.min)?\.js|ng-version='),
    ("js_framework", "jQuery",   r"jquery[.-]([\d.]+)(?:\.min)?\.js",
                                             "body", r'jquery[.-]([\d.]+)(?:\.min)?\.js'),
    ("js_framework", "Svelte",   None,       "body", r'__svelte__|svelte-kit'),
    ("js_framework", "Next.js",  None,       "body", r'__NEXT_DATA__|/_next/static/'),
    ("js_framework", "Nuxt.js",  None,       "body", r'__nuxt__|/_nuxt/'),
    ("js_framework", "Ember.js", None,       "body", r'ember(?:\.min)?\.js|Ember\.VERSION'),
    ("js_framework", "Backbone.js",None,     "body", r'backbone(?:\.min)?\.js'),

    # Backend Frameworks
    ("framework", "Laravel",     None, "cookie",     r'laravel_session|XSRF-TOKEN'),
    ("framework", "Laravel",     None, "body",       r'window\.Laravel\s*='),
    ("framework", "Django",      None, "cookie",     r'csrftoken'),
    ("framework", "Django",      None, "body",       r'csrfmiddlewaretoken'),
    ("framework", "Rails",       None, "cookie",     r'_session_id'),
    ("framework", "Rails",       None, "header_key", "x-runtime"),
    ("framework", "Spring",      None, "header_key", "x-application-context"),
    ("framework", "FastAPI",     None, "body",       r'"openapi":"[\d.]+"'),
    ("framework", "WooCommerce", None, "body",       r'woocommerce|/wc-api/'),
    ("framework", "Symfony",     None, "cookie",     r'symfony|sf_redirect'),
    ("framework", "CodeIgniter", None, "cookie",     r'ci_session'),
    ("framework", "Flask",       None, "cookie",     r'session=\.'),
    ("framework", "Struts",      None, "header_val", "x-powered-by"),

    # CDN
    ("cdn", "Cloudflare",    None, "header_key", "cf-ray"),
    ("cdn", "Cloudflare",    None, "header_key", "cf-cache-status"),
    ("cdn", "AWS CloudFront",None, "header_key", "x-amz-cf-id"),
    ("cdn", "AWS CloudFront",None, "header_val", "via"),
    ("cdn", "Fastly",        None, "header_key", "x-fastly-request-id"),
    ("cdn", "Fastly",        None, "header_val", "fastly-debug-digest"),
    ("cdn", "Akamai",        None, "header_key", "x-check-cacheable"),
    ("cdn", "Varnish",       None, "header_key", "x-varnish"),
    ("cdn", "Varnish",       None, "header_val", "via"),
    ("cdn", "Sucuri",        None, "header_key", "x-sucuri-id"),
    ("cdn", "BunnyCDN",      None, "header_key", "cdn-pullzone"),
    ("cdn", "KeyCDN",        None, "header_key", "x-edge-location"),

    # WAF
    ("waf", "Cloudflare WAF", None, "body",       r'cf-chl-bypass|Cloudflare Ray ID|__cf_chl'),
    ("waf", "Cloudflare WAF", None, "header_key", "cf-ray"),
    ("waf", "ModSecurity",    None, "body",       r'ModSecurity|mod_security|NAXSI'),
    ("waf", "AWS WAF",        None, "header_key", "x-amzn-requestid"),
    ("waf", "Imperva",        None, "cookie",     r'incap_ses|visid_incap'),
    ("waf", "Imperva",        None, "body",       r'/_Incapsula_Resource'),
    ("waf", "Sucuri WAF",     None, "header_key", "x-sucuri-id"),
    ("waf", "Barracuda",      None, "cookie",     r'barra_counter_session'),
    ("waf", "F5 BIG-IP",      None, "cookie",     r'BIGipServer|F5_HT_shrinked'),

    # Security Headers (present = good)
    ("sec_header", "HSTS",               None, "header_key", "strict-transport-security"),
    ("sec_header", "CSP",                None, "header_key", "content-security-policy"),
    ("sec_header", "X-Frame-Options",    None, "header_key", "x-frame-options"),
    ("sec_header", "X-XSS-Protection",   None, "header_key", "x-xss-protection"),
    ("sec_header", "X-Content-Type",     None, "header_key", "x-content-type-options"),
    ("sec_header", "Referrer-Policy",    None, "header_key", "referrer-policy"),
    ("sec_header", "Permissions-Policy", None, "header_key", "permissions-policy"),
]

_ALL_SEC_HEADERS = {
    "HSTS", "CSP", "X-Frame-Options", "X-XSS-Protection",
    "X-Content-Type", "Referrer-Policy", "Permissions-Policy",
}

_CATEGORY_ICON = {
    "server":       "🖥",
    "language":     "💻",
    "cms":          "📝",
    "js_framework": "⚡",
    "framework":    "🔧",
    "cdn":          "🌐",
    "waf":          "🛡",
    "sec_header":   "🔒",
}

_CATEGORY_LABEL = {
    "server":       "Web Server",
    "language":     "Language / Runtime",
    "cms":          "CMS / Platform",
    "js_framework": "JS Framework",
    "framework":    "Backend Framework",
    "cdn":          "CDN",
    "waf":          "WAF",
    "sec_header":   "Security Headers",
}

_CATEGORY_COLOR = {
    "server":       "bright_cyan",
    "language":     "cyan",
    "cms":          "bright_blue",
    "js_framework": "bright_yellow",
    "framework":    "yellow",
    "cdn":          "bright_magenta",
    "waf":          "bright_green",
    "sec_header":   "green",
}


# ── Data models ───────────────────────────────────────────────────────

@dataclass
class Tech:
    category: str
    name:     str
    version:  str = ""
    source:   str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TechResult:
    target:           str
    url:              str   = ""
    final_url:        str   = ""
    status_code:      int   = 0
    technologies:     list  = field(default_factory=list)
    missing_sec_hdrs: list  = field(default_factory=list)
    raw_headers:      dict  = field(default_factory=dict)
    timestamp:        str   = ""
    elapsed_sec:      float = 0.0
    error:            str   = ""

    def by_category(self, cat: str) -> list[Tech]:
        seen, out = set(), []
        for t in self.technologies:
            if t.category == cat and t.name not in seen:
                seen.add(t.name)
                out.append(t)
        return out

    def to_dict(self) -> dict:
        return {
            "target":           self.target,
            "module":           "tech",
            "url":              self.url,
            "final_url":        self.final_url,
            "status_code":      self.status_code,
            "timestamp":        self.timestamp,
            "elapsed_sec":      self.elapsed_sec,
            "error":            self.error,
            "missing_sec_hdrs": self.missing_sec_hdrs,
            "technologies":     [t.to_dict() for t in self.technologies],
        }


# ── Fingerprinter ─────────────────────────────────────────────────────

class TechFingerprinter:
    """
    Fingerprint a web target's technology stack from HTTP headers + HTML body.

    Args:
        target          : URL or domain (e.g. "https://example.com" or "example.com")
        timeout         : HTTP request timeout in seconds (default 12)
        follow_redirects: Follow HTTP redirects (default True)
        verify_ssl      : Verify TLS certificate (default False — avoids failures on bug bounty targets)
    """

    _HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) "
            "Gecko/20100101 Firefox/120.0"
        ),
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection":      "keep-alive",
    }

    def __init__(
        self,
        target:           str,
        timeout:          int  = 12,
        follow_redirects: bool = True,
        verify_ssl:       bool = False,
    ):
        self.target           = target.strip()
        self.timeout          = timeout
        self.follow_redirects = follow_redirects
        self.verify_ssl       = verify_ssl

    # ── Public ────────────────────────────────────────────────

    def run(self) -> TechResult:
        section_header("Technology Fingerprinter", "🔬")

        url = self._normalise_url(self.target)
        info(f"Target     : [accent]{url}[/accent]")

        start  = time.time()
        result = TechResult(
            target    = self.target,
            url       = url,
            timestamp = datetime.utcnow().isoformat() + "Z",
        )

        # ── Fetch ─────────────────────────────────────────────
        resp = self._fetch(url)
        if resp is None:
            # Try HTTP if HTTPS failed
            if url.startswith("https://"):
                http_url = url.replace("https://", "http://", 1)
                warn(f"HTTPS failed — retrying: [accent]{http_url}[/accent]")
                resp = self._fetch(http_url)

        if resp is None:
            result.error       = f"Could not connect to {url}"
            result.elapsed_sec = round(time.time() - start, 2)
            error(result.error)
            return result

        result.final_url   = resp.url
        result.status_code = resp.status_code
        result.elapsed_sec = round(time.time() - start, 2)
        result.raw_headers = dict(resp.headers)

        info(f"Status     : [accent]{resp.status_code}[/accent]")
        info(f"Final URL  : [accent]{resp.url}[/accent]")
        info(f"Response   : [accent]{len(resp.content):,}[/accent] bytes\n")

        # ── Fingerprint ───────────────────────────────────────
        cookies_str = "; ".join(
            f"{k}={v}" for k, v in resp.cookies.items()
        )
        # Also include raw Set-Cookie header for pattern matching
        cookies_str += "; " + resp.headers.get("Set-Cookie", "")

        techs = _run_fingerprints(resp.headers, resp.text, cookies_str)
        result.technologies = techs

        # ── Missing security headers ──────────────────────────
        present_sec = {t.name for t in techs if t.category == "sec_header"}
        result.missing_sec_hdrs = sorted(_ALL_SEC_HEADERS - present_sec)

        self._display(result)
        return result

    # ── HTTP ──────────────────────────────────────────────────

    def _fetch(self, url: str) -> Optional[requests.Response]:
        try:
            resp = requests.get(
                url,
                headers      = self._HEADERS,
                timeout      = self.timeout,
                allow_redirects = self.follow_redirects,
                verify       = self.verify_ssl,
            )
            return resp
        except requests.exceptions.SSLError:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.Timeout:
            warn(f"Request timed out after {self.timeout}s")
            return None
        except Exception as e:
            warn(f"Request error: {e}")
            return None

    @staticmethod
    def _normalise_url(target: str) -> str:
        """Ensure the target is a full URL."""
        t = target.strip().rstrip("/")
        if not t.startswith(("http://", "https://")):
            return f"https://{t}"
        return t

    # ── Rich display ──────────────────────────────────────────

    def _display(self, result: TechResult):
        cats_with_results = [
            c for c in _CATEGORY_LABEL
            if result.by_category(c) and c != "sec_header"
        ]

        if not cats_with_results and not result.technologies:
            warn("No technologies identified from headers or body.")
            warn("Target may be behind a WAF that strips identifying headers.")
            return

        # Main technologies table
        table = Table(
            show_header  = True,
            header_style = "bold cyan",
            box          = box.SIMPLE_HEAD,
            pad_edge     = False,
            show_edge    = False,
        )
        table.add_column("CATEGORY",    style="dim white",  width=22)
        table.add_column("TECHNOLOGY",  style="bold white", min_width=18)
        table.add_column("VERSION",     style="dim white",  width=14)
        table.add_column("SOURCE",      style="dim white",  width=14)

        for cat in _CATEGORY_LABEL:
            if cat == "sec_header":
                continue
            items = result.by_category(cat)
            if not items:
                continue
            color = _CATEGORY_COLOR.get(cat, "white")
            icon  = _CATEGORY_ICON.get(cat, "")
            label = _CATEGORY_LABEL.get(cat, cat)
            for i, t in enumerate(items):
                cat_cell = (
                    f"[{color}]{icon} {label}[/{color}]"
                    if i == 0 else ""
                )
                table.add_row(
                    cat_cell,
                    f"[{color}]{escape(t.name)}[/{color}]",
                    escape(t.version) or "[dim]—[/dim]",
                    f"[dim]{t.source}[/dim]",
                )

        console.print(table)

        # Security headers
        present = result.by_category("sec_header")
        missing = result.missing_sec_hdrs

        sec_lines = []
        for t in present:
            sec_lines.append(f"  [green]✓[/green]  {t.name}")
        for name in missing:
            sec_lines.append(f"  [red]✗[/red]  [dim]{name}[/dim]")

        if sec_lines:
            sec_score = len(present)
            sec_total = len(_ALL_SEC_HEADERS)
            color     = "green" if sec_score >= 5 else "yellow" if sec_score >= 3 else "red"
            console.print(
                Panel(
                    "\n".join(sec_lines),
                    title  = f"[bold {color}]🔒 Security Headers  {sec_score}/{sec_total}[/bold {color}]",
                    border_style = color,
                    box    = box.ROUNDED,
                    padding = (0, 1),
                )
            )

        summary_panel("Tech Fingerprint Complete", {
            "Target":         result.target,
            "Status":         str(result.status_code),
            "Technologies":   str(len(set(t.name for t in result.technologies
                                          if t.category != "sec_header"))),
            "Sec headers":    f"{len(present)}/{len(_ALL_SEC_HEADERS)} present",
            "Missing":        ", ".join(missing) or "none",
            "Time":           f"{result.elapsed_sec:.2f}s",
        }, accent_color="bright_cyan")


# ── Core fingerprint engine ───────────────────────────────────────────

def _run_fingerprints(
    headers: requests.structures.CaseInsensitiveDict,
    body:    str,
    cookies: str,
) -> list[Tech]:
    """Match all fingerprint signatures against response data."""
    found    = []
    seen     = set()   # (category, name) — dedup
    hdrs_low = {k.lower(): v for k, v in headers.items()}

    for (cat, name, ver_pat, match_type, pattern) in _FP:
        version = ""
        matched = False

        if match_type == "header_key":
            matched = pattern.lower() in hdrs_low
            if matched and ver_pat:
                m = re.search(ver_pat, hdrs_low.get(pattern.lower(), ""), re.I)
                version = (m.group(1) or "") if (m and m.lastindex) else ""

        elif match_type == "header_val":
            val = hdrs_low.get(pattern.lower(), "")
            if val:
                m = re.search(ver_pat or r".", val, re.I)
                matched = bool(m)
                if matched and ver_pat and m.lastindex:
                    version = m.group(1) or ""

        elif match_type == "body":
            m = re.search(pattern, body, re.I | re.S)
            matched = bool(m)
            if matched and ver_pat:
                mv = re.search(ver_pat, body, re.I | re.S)
                if mv and mv.lastindex:
                    version = mv.group(1) or ""

        elif match_type == "cookie":
            matched = bool(re.search(pattern, cookies, re.I))

        key = (cat, name)
        if matched and key not in seen:
            seen.add(key)
            found.append(Tech(
                category = cat,
                name     = name,
                version  = version.strip(),
                source   = match_type,
            ))

    return found