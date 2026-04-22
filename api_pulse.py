"""
API Pulse — The Developer's API Swiss Army Knife
Probe, benchmark, compare, and diagnose any API from your terminal.
"""

import argparse
import json
import statistics
import sys
import time
import ssl
import socket
import concurrent.futures
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from typing import Any

# Use only stdlib for zero-dependency core
import http.client
import urllib.request
import urllib.error


# ─── Data Classes ────────────────────────────────────────────────────

@dataclass
class ResponseRecord:
    """Single API call result."""
    status: int
    latency_ms: float
    size_bytes: int
    headers: dict
    body: str = ""
    error: str = ""
    timestamp: float = 0.0


@dataclass
class EndpointReport:
    """Aggregated stats for one endpoint."""
    url: str
    method: str
    responses: list[ResponseRecord] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.responses)

    @property
    def success_count(self) -> int:
        return sum(1 for r in self.responses if 200 <= r.status < 400)

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.responses if r.status >= 400 or r.error)

    @property
    def success_rate(self) -> float:
        return (self.success_count / self.total * 100) if self.total else 0

    @property
    def latencies(self) -> list[float]:
        return [r.latency_ms for r in self.responses if not r.error]

    @property
    def avg_latency(self) -> float:
        return statistics.mean(self.latencies) if self.latencies else 0

    @property
    def median_latency(self) -> float:
        return statistics.median(self.latencies) if self.latencies else 0

    @property
    def p95_latency(self) -> float:
        if not self.latencies:
            return 0
        sorted_l = sorted(self.latencies)
        idx = int(len(sorted_l) * 0.95)
        return sorted_l[min(idx, len(sorted_l) - 1)]

    @property
    def p99_latency(self) -> float:
        if not self.latencies:
            return 0
        sorted_l = sorted(self.latencies)
        idx = int(len(sorted_l) * 0.99)
        return sorted_l[min(idx, len(sorted_l) - 1)]

    @property
    def min_latency(self) -> float:
        return min(self.latencies) if self.latencies else 0

    @property
    def max_latency(self) -> float:
        return max(self.latencies) if self.latencies else 0

    @property
    def std_dev(self) -> float:
        return statistics.stdev(self.latencies) if len(self.latencies) > 1 else 0

    @property
    def avg_size(self) -> float:
        sizes = [r.size_bytes for r in self.responses if not r.error]
        return statistics.mean(sizes) if sizes else 0

    @property
    def requests_per_sec(self) -> float:
        if not self.responses:
            return 0
        timestamps = [r.timestamp for r in self.responses]
        duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 1
        return self.total / max(duration, 0.001)

    @property
    def status_distribution(self) -> dict[int, int]:
        dist = defaultdict(int)
        for r in self.responses:
            dist[r.status] += 1
        return dict(dist)

    def latency_grade(self) -> str:
        avg = self.avg_latency
        if avg < 100:
            return "A+"
        if avg < 200:
            return "A"
        if avg < 500:
            return "B"
        if avg < 1000:
            return "C"
        if avg < 3000:
            return "D"
        return "F"


# ─── HTTP Engine ─────────────────────────────────────────────────────

def make_request(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: str | None = None,
    timeout: int = 10,
) -> ResponseRecord:
    """Make a single HTTP request and measure everything."""
    headers = headers or {}
    headers.setdefault("User-Agent", "api-pulse/1.0")

    req = urllib.request.Request(url, method=method, headers=headers)
    if body:
        req.data = body.encode("utf-8")
        headers.setdefault("Content-Type", "application/json")

    start = time.perf_counter()
    timestamp = time.time()
    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            resp_body = resp.read()
            elapsed = (time.perf_counter() - start) * 1000
            return ResponseRecord(
                status=resp.status,
                latency_ms=elapsed,
                size_bytes=len(resp_body),
                headers=dict(resp.headers),
                body=resp_body.decode("utf-8", errors="replace")[:2000],
                timestamp=timestamp,
            )
    except urllib.error.HTTPError as e:
        elapsed = (time.perf_counter() - start) * 1000
        body_text = ""
        try:
            body_text = e.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            pass
        return ResponseRecord(
            status=e.code,
            latency_ms=elapsed,
            size_bytes=0,
            headers=dict(e.headers) if e.headers else {},
            body=body_text,
            timestamp=timestamp,
        )
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return ResponseRecord(
            status=0,
            latency_ms=elapsed,
            size_bytes=0,
            headers={},
            error=str(e),
            timestamp=timestamp,
        )


# ─── SSL / TLS Inspector ────────────────────────────────────────────

def inspect_tls(url: str) -> dict:
    """Inspect TLS certificate and connection details."""
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        return {"tls": False, "reason": "Not HTTPS"}

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                # Parse expiry
                not_after = cert.get("notAfter", "")
                not_before = cert.get("notBefore", "")
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))

                # Days until expiry
                days_left = None
                if not_after:
                    try:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry - datetime.utcnow()).days
                    except ValueError:
                        pass

                return {
                    "tls": True,
                    "version": version,
                    "cipher": cipher[0] if cipher else "Unknown",
                    "cipher_bits": cipher[2] if cipher else 0,
                    "subject": subject.get("commonName", "Unknown"),
                    "issuer": issuer.get("organizationName", "Unknown"),
                    "not_before": not_before,
                    "not_after": not_after,
                    "days_until_expiry": days_left,
                    "san": [
                        entry[1]
                        for entry in cert.get("subjectAltName", [])
                        if entry[0] == "DNS"
                    ][:5],
                }
    except Exception as e:
        return {"tls": True, "error": str(e)}


# ─── Security Header Audit ──────────────────────────────────────────

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "label": "HSTS",
        "severity": "high",
        "desc": "Forces browsers to use HTTPS",
    },
    "Content-Security-Policy": {
        "label": "CSP",
        "severity": "high",
        "desc": "Prevents XSS and injection attacks",
    },
    "X-Content-Type-Options": {
        "label": "X-Content-Type-Options",
        "severity": "medium",
        "desc": "Prevents MIME-type sniffing",
    },
    "X-Frame-Options": {
        "label": "X-Frame-Options",
        "severity": "medium",
        "desc": "Prevents clickjacking",
    },
    "X-XSS-Protection": {
        "label": "X-XSS-Protection",
        "severity": "low",
        "desc": "Legacy XSS filter (modern CSP is better)",
    },
    "Referrer-Policy": {
        "label": "Referrer-Policy",
        "severity": "low",
        "desc": "Controls referrer information leakage",
    },
    "Permissions-Policy": {
        "label": "Permissions-Policy",
        "severity": "medium",
        "desc": "Controls browser feature access",
    },
}


def audit_security_headers(headers: dict) -> list[dict]:
    """Audit response headers for security best practices."""
    results = []
    # Normalize header keys to title case for comparison
    normalized = {k.title(): v for k, v in headers.items()}

    for header, info in SECURITY_HEADERS.items():
        present = header in normalized or header.lower() in {k.lower() for k in headers}
        results.append({
            "header": header,
            "label": info["label"],
            "present": present,
            "severity": info["severity"],
            "desc": info["desc"],
            "value": normalized.get(header, ""),
        })
    return results


def security_score(audit: list[dict]) -> int:
    """Calculate a 0-100 security header score."""
    weights = {"high": 25, "medium": 15, "low": 10}
    total = sum(weights[h["severity"]] for h in audit)
    earned = sum(weights[h["severity"]] for h in audit if h["present"])
    return int((earned / total) * 100) if total else 0


# ─── Benchmarker ─────────────────────────────────────────────────────

def benchmark(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: str | None = None,
    requests_count: int = 50,
    concurrency: int = 5,
    timeout: int = 10,
) -> EndpointReport:
    """Benchmark an endpoint with concurrent requests."""
    report = EndpointReport(url=url, method=method)

    def _do_request(_: int) -> ResponseRecord:
        return make_request(url, method, headers, body, timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(_do_request, i) for i in range(requests_count)]
        for future in concurrent.futures.as_completed(futures):
            report.responses.append(future.result())

    return report


# ─── Chain Tester ────────────────────────────────────────────────────

def run_chain(chain: list[dict], verbose: bool = False) -> list[dict]:
    """Run a sequence of API calls, passing data between them."""
    results = []
    context = {}  # Shared variables between chain steps

    for i, step in enumerate(chain):
        url = step["url"]
        method = step.get("method", "GET")
        headers = step.get("headers", {})
        body = step.get("body")
        extract = step.get("extract", {})
        name = step.get("name", f"Step {i + 1}")

        # Substitute context variables
        for key, val in context.items():
            url = url.replace(f"{{{{{key}}}}}", str(val))
            if body:
                body = body.replace(f"{{{{{key}}}}}", str(val))

        resp = make_request(url, method, headers, body)

        # Extract values for next steps
        extracted = {}
        if extract and resp.body:
            try:
                data = json.loads(resp.body)
                for var_name, json_path in extract.items():
                    keys = json_path.strip("$.").split(".")
                    val = data
                    for k in keys:
                        if isinstance(val, dict):
                            val = val.get(k)
                        elif isinstance(val, list) and k.isdigit():
                            val = val[int(k)]
                        else:
                            val = None
                            break
                    if val is not None:
                        context[var_name] = val
                        extracted[var_name] = val
            except (json.JSONDecodeError, TypeError):
                pass

        result = {
            "name": name,
            "url": url,
            "method": method,
            "status": resp.status,
            "latency_ms": resp.latency_ms,
            "size_bytes": resp.size_bytes,
            "error": resp.error,
            "extracted": extracted,
        }
        results.append(result)

        if verbose:
            status_icon = "✅" if 200 <= resp.status < 400 else "❌"
            print(f"  {status_icon} {name}: {method} {url} → {resp.status} ({resp.latency_ms:.0f}ms)")
            if extracted:
                for k, v in extracted.items():
                    print(f"     📦 Extracted {k} = {v}")

        # Stop chain if a step fails critically
        if resp.status == 0 and resp.error:
            break

    return results


# ─── Terminal Report ─────────────────────────────────────────────────

def print_probe_report(resp: ResponseRecord, url: str, tls_info: dict, audit: list[dict]) -> None:
    """Print a detailed probe report for a single URL."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    console = Console()

    # Header
    status_color = "green" if 200 <= resp.status < 400 else "yellow" if resp.status < 500 else "red"
    header = Text()
    header.append("🔍 API PULSE", style="bold magenta")
    header.append(f"  —  Probe Report\n\n", style="dim")
    header.append(f"URL: ", style="bold")
    header.append(f"{url}\n", style="cyan")
    header.append(f"Status: ", style="bold")
    header.append(f"{resp.status}", style=f"bold {status_color}")
    header.append(f"  •  ", style="dim")
    header.append(f"Latency: {resp.latency_ms:.0f}ms", style="cyan")
    header.append(f"  •  ", style="dim")
    header.append(f"Size: {resp.size_bytes:,} bytes", style="cyan")
    console.print(Panel(header, border_style="magenta", expand=False))

    # Response Headers
    if resp.headers:
        h_table = Table(title="📋 Response Headers", border_style="blue", show_lines=False)
        h_table.add_column("Header", style="bold cyan", width=30)
        h_table.add_column("Value", style="dim")
        important = [
            "Content-Type", "Server", "Cache-Control", "X-Powered-By",
            "Access-Control-Allow-Origin", "Set-Cookie",
        ]
        for key in important:
            val = resp.headers.get(key) or resp.headers.get(key.lower())
            if val:
                h_table.add_row(key, str(val)[:80])
        # Show any security-relevant ones
        for key, val in resp.headers.items():
            if key.lower().startswith(("x-", "strict", "content-security", "referrer", "permissions")):
                if key not in important:
                    h_table.add_row(key, str(val)[:80])
        console.print(h_table)
        console.print()

    # TLS Info
    if tls_info.get("tls"):
        console.print("[bold magenta]🔒 TLS / SSL[/]\n")
        if tls_info.get("error"):
            console.print(f"  [red]Error: {tls_info['error']}[/]")
        else:
            days = tls_info.get("days_until_expiry")
            days_color = "green" if days and days > 30 else "yellow" if days and days > 7 else "red"
            tls_table = Table(show_header=False, border_style="green")
            tls_table.add_column("Field", style="bold", width=22)
            tls_table.add_column("Value", style="cyan")
            tls_table.add_row("Protocol", tls_info.get("version", "—"))
            tls_table.add_row("Cipher", f"{tls_info.get('cipher', '—')} ({tls_info.get('cipher_bits', 0)} bits)")
            tls_table.add_row("Subject", tls_info.get("subject", "—"))
            tls_table.add_row("Issuer", tls_info.get("issuer", "—"))
            tls_table.add_row("Valid until", tls_info.get("not_after", "—"))
            tls_table.add_row("Days remaining", f"[{days_color}]{days}[/]" if days else "—")
            if tls_info.get("san"):
                tls_table.add_row("Alt names", ", ".join(tls_info["san"][:3]))
            console.print(tls_table)
        console.print()

    # Security Audit
    console.print("[bold magenta]🛡️ Security Header Audit[/]\n")
    score = security_score(audit)
    score_color = "green" if score >= 70 else "yellow" if score >= 40 else "red"
    console.print(f"  Score: [bold {score_color}]{score}/100[/]\n")

    s_table = Table(border_style="yellow")
    s_table.add_column("Header", style="bold")
    s_table.add_column("Status", justify="center")
    s_table.add_column("Severity", justify="center")
    s_table.add_column("Purpose", style="dim")
    for h in audit:
        status = "[green]✅ Present[/]" if h["present"] else "[red]❌ Missing[/]"
        sev_color = {"high": "red", "medium": "yellow", "low": "dim"}.get(h["severity"], "dim")
        s_table.add_row(h["label"], status, f"[{sev_color}]{h['severity']}[/]", h["desc"])
    console.print(s_table)
    console.print()


def print_benchmark_report(report: EndpointReport) -> None:
    """Print benchmark results."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    console = Console()

    grade = report.latency_grade()
    grade_color = {
        "A+": "bold green", "A": "green", "B": "yellow",
        "C": "yellow", "D": "red", "F": "bold red",
    }.get(grade, "dim")

    header = Text()
    header.append("⚡ API PULSE", style="bold magenta")
    header.append(f"  —  Benchmark Report\n\n", style="dim")
    header.append(f"{report.method} ", style="bold yellow")
    header.append(f"{report.url}\n", style="cyan")
    header.append(f"{report.total} requests  •  ", style="dim")
    header.append(f"Grade: ", style="bold")
    header.append(f"{grade}", style=grade_color)
    console.print(Panel(header, border_style="magenta", expand=False))

    # Stats table
    stats = Table(title="📊 Latency Statistics (ms)", show_header=False, border_style="cyan")
    stats.add_column("Metric", style="bold", width=20)
    stats.add_column("Value", justify="right", style="cyan", width=15)
    stats.add_row("Average", f"{report.avg_latency:.1f}")
    stats.add_row("Median (p50)", f"{report.median_latency:.1f}")
    stats.add_row("p95", f"{report.p95_latency:.1f}")
    stats.add_row("p99", f"{report.p99_latency:.1f}")
    stats.add_row("Min", f"{report.min_latency:.1f}")
    stats.add_row("Max", f"{report.max_latency:.1f}")
    stats.add_row("Std Dev", f"{report.std_dev:.1f}")
    stats.add_row("Avg Size", f"{report.avg_size:.0f} bytes")
    stats.add_row("Requests/sec", f"{report.requests_per_sec:.1f}")
    console.print(stats)
    console.print()

    # Status distribution
    dist = report.status_distribution
    if dist:
        console.print("[bold magenta]📶 Status Code Distribution[/]\n")
        for code, count in sorted(dist.items()):
            bar_len = int((count / report.total) * 40)
            color = "green" if 200 <= code < 300 else "yellow" if code < 400 else "red"
            pct = count / report.total * 100
            bar = "█" * bar_len
            console.print(f"  [{color}]{code}[/] {bar} {count} ({pct:.0f}%)")
        console.print()

    # Success rate
    sr = report.success_rate
    sr_color = "green" if sr >= 99 else "yellow" if sr >= 95 else "red"
    console.print(f"  Success rate: [bold {sr_color}]{sr:.1f}%[/] ({report.success_count}/{report.total})")

    # Latency histogram (ASCII)
    if report.latencies:
        console.print("\n[bold magenta]📈 Latency Distribution[/]\n")
        buckets = 10
        mn, mx = min(report.latencies), max(report.latencies)
        if mx > mn:
            step = (mx - mn) / buckets
            counts = [0] * buckets
            for l in report.latencies:
                idx = min(int((l - mn) / step), buckets - 1)
                counts[idx] += 1
            max_count = max(counts)
            for i in range(buckets):
                low = mn + i * step
                high = low + step
                bar_len = int((counts[i] / max_count) * 30) if max_count else 0
                bar = "▓" * bar_len
                console.print(f"  {low:7.0f}-{high:5.0f}ms │ {bar} {counts[i]}")
    console.print()


def print_compare_report(reports: list[EndpointReport]) -> None:
    """Print side-by-side comparison of multiple endpoints."""
    from rich.console import Console
    from rich.table import Table

    console = Console()
    console.print("\n[bold magenta]🔀 API PULSE — Comparison Report[/]\n")

    table = Table(border_style="magenta")
    table.add_column("Metric", style="bold")
    for r in reports:
        parsed = urlparse(r.url)
        label = parsed.hostname or r.url
        table.add_column(label[:25], justify="right", style="cyan")

    def best_lowest(values):
        min_val = min(values) if values else 0
        return [f"[bold green]{v:.1f} 🏆[/]" if v == min_val and v > 0 else f"{v:.1f}" for v in values]

    def best_highest(values):
        max_val = max(values) if values else 0
        return [f"[bold green]{v:.1f} 🏆[/]" if v == max_val and v > 0 else f"{v:.1f}" for v in values]

    def add_row_lowest(label, values):
        formatted = best_lowest(values)
        table.add_row(label, *formatted)

    def add_row_highest(label, values):
        formatted = best_highest(values)
        table.add_row(label, *formatted)

    table.add_row("Grade", *[r.latency_grade() for r in reports])
    add_row_lowest("Avg Latency (ms)", [r.avg_latency for r in reports])
    add_row_lowest("Median (ms)", [r.median_latency for r in reports])
    add_row_lowest("p95 (ms)", [r.p95_latency for r in reports])
    add_row_lowest("p99 (ms)", [r.p99_latency for r in reports])
    add_row_lowest("Min (ms)", [r.min_latency for r in reports])
    add_row_lowest("Max (ms)", [r.max_latency for r in reports])
    add_row_highest("Success Rate (%)", [r.success_rate for r in reports])
    add_row_highest("Req/sec", [r.requests_per_sec for r in reports])
    table.add_row("Avg Size", *[f"{r.avg_size:.0f}B" for r in reports])

    console.print(table)
    console.print()


def print_chain_report(results: list[dict]) -> None:
    """Print chain test results."""
    from rich.console import Console
    from rich.table import Table

    console = Console()
    console.print("\n[bold magenta]🔗 API PULSE — Chain Test Report[/]\n")

    table = Table(border_style="cyan")
    table.add_column("#", style="bold", width=4)
    table.add_column("Step", style="bold cyan")
    table.add_column("Method", width=7)
    table.add_column("Status", justify="center")
    table.add_column("Latency", justify="right")
    table.add_column("Extracted", style="dim")

    total_time = 0
    all_pass = True
    for i, r in enumerate(results):
        status_color = "green" if 200 <= r["status"] < 400 else "red"
        if r["status"] >= 400 or r["error"]:
            all_pass = False
        total_time += r["latency_ms"]
        extracted = ", ".join(f"{k}={v}" for k, v in r.get("extracted", {}).items()) or "—"
        table.add_row(
            str(i + 1),
            r["name"],
            r["method"],
            f"[{status_color}]{r['status']}[/]",
            f"{r['latency_ms']:.0f}ms",
            extracted,
        )

    console.print(table)
    result_color = "green" if all_pass else "red"
    result_text = "ALL PASSED ✅" if all_pass else "FAILED ❌"
    console.print(f"\n  Result: [bold {result_color}]{result_text}[/]")
    console.print(f"  Total time: [bold]{total_time:.0f}ms[/] across {len(results)} steps")
    console.print()


# ─── HTML Report Generator ──────────────────────────────────────────

def generate_html_report(
    url: str,
    probe_resp: ResponseRecord | None,
    tls_info: dict | None,
    audit: list[dict] | None,
    bench: EndpointReport | None,
    output: Path,
) -> None:
    """Generate a gorgeous standalone HTML report."""
    sections = []

    # Probe section
    if probe_resp:
        status_class = "good" if 200 <= probe_resp.status < 400 else "warn" if probe_resp.status < 500 else "bad"
        sec_score = security_score(audit) if audit else 0
        sec_class = "good" if sec_score >= 70 else "warn" if sec_score >= 40 else "bad"

        audit_rows = ""
        if audit:
            for h in audit:
                icon = "✅" if h["present"] else "❌"
                audit_rows += f'<tr><td>{h["label"]}</td><td>{icon}</td><td class="sev-{h["severity"]}">{h["severity"]}</td><td class="dim">{h["desc"]}</td></tr>'

        tls_html = ""
        if tls_info and tls_info.get("tls") and not tls_info.get("error"):
            days = tls_info.get("days_until_expiry", 0)
            days_class = "good" if days and days > 30 else "warn" if days and days > 7 else "bad"
            tls_html = f"""
            <div class="card">
                <h3>🔒 TLS / SSL</h3>
                <div class="grid-2">
                    <div class="kv"><span>Protocol</span><span>{tls_info.get('version','—')}</span></div>
                    <div class="kv"><span>Cipher</span><span>{tls_info.get('cipher','—')}</span></div>
                    <div class="kv"><span>Issuer</span><span>{tls_info.get('issuer','—')}</span></div>
                    <div class="kv"><span>Days left</span><span class="{days_class}">{days}</span></div>
                </div>
            </div>"""

        sections.append(f"""
        <div class="card">
            <h3>🔍 Probe Results</h3>
            <div class="big-stats">
                <div class="big-stat"><div class="big-num {status_class}">{probe_resp.status}</div><div class="big-label">Status</div></div>
                <div class="big-stat"><div class="big-num">{probe_resp.latency_ms:.0f}ms</div><div class="big-label">Latency</div></div>
                <div class="big-stat"><div class="big-num">{probe_resp.size_bytes:,}B</div><div class="big-label">Size</div></div>
                <div class="big-stat"><div class="big-num {sec_class}">{sec_score}/100</div><div class="big-label">Security</div></div>
            </div>
        </div>
        {tls_html}
        <div class="card">
            <h3>🛡️ Security Headers</h3>
            <table><thead><tr><th>Header</th><th>Status</th><th>Severity</th><th>Purpose</th></tr></thead>
            <tbody>{audit_rows}</tbody></table>
        </div>""")

    # Benchmark section
    if bench and bench.latencies:
        grade = bench.latency_grade()
        grade_class = "good" if grade.startswith("A") else "warn" if grade == "B" else "bad"

        # Build histogram data for CSS bar chart
        buckets = 12
        mn, mx = min(bench.latencies), max(bench.latencies)
        step = (mx - mn) / buckets if mx > mn else 1
        counts = [0] * buckets
        for l in bench.latencies:
            idx = min(int((l - mn) / step), buckets - 1)
            counts[idx] += 1
        max_count = max(counts) if counts else 1

        bars_html = ""
        for i in range(buckets):
            height = (counts[i] / max_count) * 100 if max_count else 0
            low = mn + i * step
            bars_html += f'<div class="bar-wrap"><div class="bar" style="height:{height}%"><span class="bar-val">{counts[i]}</span></div><div class="bar-label">{low:.0f}</div></div>'

        dist_html = ""
        for code, count in sorted(bench.status_distribution.items()):
            pct = count / bench.total * 100
            code_class = "good" if 200 <= code < 300 else "warn" if code < 400 else "bad"
            dist_html += f'<div class="status-row"><span class="status-code {code_class}">{code}</span><div class="status-bar-bg"><div class="status-bar {code_class}" style="width:{pct}%"></div></div><span>{count} ({pct:.0f}%)</span></div>'

        sections.append(f"""
        <div class="card">
            <h3>⚡ Benchmark Results</h3>
            <div class="big-stats">
                <div class="big-stat"><div class="big-num {grade_class}">{grade}</div><div class="big-label">Grade</div></div>
                <div class="big-stat"><div class="big-num">{bench.avg_latency:.0f}ms</div><div class="big-label">Avg Latency</div></div>
                <div class="big-stat"><div class="big-num">{bench.p95_latency:.0f}ms</div><div class="big-label">p95</div></div>
                <div class="big-stat"><div class="big-num">{bench.success_rate:.0f}%</div><div class="big-label">Success</div></div>
                <div class="big-stat"><div class="big-num">{bench.requests_per_sec:.1f}</div><div class="big-label">Req/sec</div></div>
            </div>
        </div>
        <div class="card">
            <h3>📈 Latency Distribution (ms)</h3>
            <div class="histogram">{bars_html}</div>
        </div>
        <div class="card">
            <h3>📶 Status Codes</h3>
            {dist_html}
        </div>
        <div class="card">
            <h3>📊 Detailed Stats</h3>
            <div class="grid-2">
                <div class="kv"><span>Median</span><span>{bench.median_latency:.1f}ms</span></div>
                <div class="kv"><span>p99</span><span>{bench.p99_latency:.1f}ms</span></div>
                <div class="kv"><span>Min</span><span>{bench.min_latency:.1f}ms</span></div>
                <div class="kv"><span>Max</span><span>{bench.max_latency:.1f}ms</span></div>
                <div class="kv"><span>Std Dev</span><span>{bench.std_dev:.1f}ms</span></div>
                <div class="kv"><span>Total Requests</span><span>{bench.total}</span></div>
            </div>
        </div>""")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>API Pulse — {url}</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
:root {{
    --bg: #06060a; --surface: #0e0e16; --surface2: #16162a;
    --border: #252540; --text: #e4e4f0; --dim: #5a5a80;
    --accent: #7c3aed; --accent2: #06b6d4; --green: #22c55e;
    --red: #ef4444; --yellow: #eab308; --magenta: #d946ef;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: var(--bg); color: var(--text); font-family: 'Syne', sans-serif; padding: 2rem; max-width: 1000px; margin: 0 auto; }}
.hero {{ text-align: center; padding: 2.5rem 1rem; border-bottom: 1px solid var(--border); margin-bottom: 2rem; }}
.hero h1 {{ font-size: 2.5rem; font-weight: 800; background: linear-gradient(135deg, var(--accent), var(--magenta), var(--accent2)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
.hero .url {{ font-family: 'Space Mono', monospace; color: var(--accent2); font-size: 1rem; margin-top: 0.5rem; word-break: break-all; }}
.hero .meta {{ color: var(--dim); font-size: 0.85rem; margin-top: 0.5rem; }}
.card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 14px; padding: 1.5rem; margin-bottom: 1.2rem; }}
.card h3 {{ font-size: 1.1rem; margin-bottom: 1rem; }}
.big-stats {{ display: flex; gap: 1rem; flex-wrap: wrap; justify-content: center; }}
.big-stat {{ text-align: center; flex: 1; min-width: 100px; padding: 1rem; background: var(--surface2); border-radius: 10px; }}
.big-num {{ font-family: 'Space Mono', monospace; font-size: 1.8rem; font-weight: 700; }}
.big-label {{ font-size: 0.75rem; color: var(--dim); margin-top: 0.3rem; text-transform: uppercase; letter-spacing: 1px; }}
.good {{ color: var(--green); }} .warn {{ color: var(--yellow); }} .bad {{ color: var(--red); }}
table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
thead th {{ text-align: left; padding: 0.5rem; border-bottom: 2px solid var(--border); color: var(--dim); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px; }}
tbody td {{ padding: 0.4rem 0.5rem; border-bottom: 1px solid var(--border); font-family: 'Space Mono', monospace; font-size: 0.8rem; }}
.dim {{ color: var(--dim); font-family: 'Syne', sans-serif; }}
.sev-high {{ color: var(--red); }} .sev-medium {{ color: var(--yellow); }} .sev-low {{ color: var(--dim); }}
.grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; }}
.kv {{ display: flex; justify-content: space-between; padding: 0.4rem 0.7rem; background: var(--surface2); border-radius: 6px; font-size: 0.85rem; }}
.kv span:first-child {{ color: var(--dim); }} .kv span:last-child {{ font-family: 'Space Mono', monospace; font-weight: 600; }}
.histogram {{ display: flex; align-items: flex-end; gap: 3px; height: 140px; padding-bottom: 1.5rem; position: relative; }}
.bar-wrap {{ flex: 1; display: flex; flex-direction: column; align-items: center; height: 100%; justify-content: flex-end; }}
.bar {{ width: 100%; background: linear-gradient(to top, var(--accent), var(--magenta)); border-radius: 4px 4px 0 0; position: relative; min-height: 3px; transition: height 0.3s; }}
.bar-val {{ position: absolute; top: -16px; font-size: 0.6rem; font-family: 'Space Mono', monospace; color: var(--text); white-space: nowrap; }}
.bar-label {{ font-size: 0.55rem; color: var(--dim); margin-top: 0.3rem; font-family: 'Space Mono', monospace; }}
.status-row {{ display: flex; align-items: center; gap: 0.7rem; margin: 0.4rem 0; font-size: 0.85rem; }}
.status-code {{ font-family: 'Space Mono', monospace; font-weight: 700; min-width: 35px; }}
.status-bar-bg {{ flex: 1; height: 8px; background: var(--surface2); border-radius: 4px; overflow: hidden; }}
.status-bar {{ height: 100%; border-radius: 4px; }}
.status-bar.good {{ background: var(--green); }} .status-bar.warn {{ background: var(--yellow); }} .status-bar.bad {{ background: var(--red); }}
footer {{ text-align: center; padding: 2rem; color: var(--dim); font-size: 0.8rem; border-top: 1px solid var(--border); margin-top: 2rem; }}
footer a {{ color: var(--accent); text-decoration: none; }}
@media (max-width: 600px) {{ body {{ padding: 1rem; }} .big-stats {{ flex-direction: column; }} .grid-2 {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<div class="hero">
    <h1>🔍 API Pulse</h1>
    <div class="url">{url}</div>
    <div class="meta">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
</div>
{"".join(sections)}
<footer>Generated by <a href="https://github.com/YOUR_USERNAME/api-pulse">api-pulse</a> — the developer's API Swiss Army knife</footer>
</body>
</html>"""

    output.write_text(html)
    print(f"📄 HTML report saved to {output}")


# ─── CLI ─────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="API Pulse — Probe, benchmark, compare, and diagnose any API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python api_pulse.py probe https://api.github.com
  python api_pulse.py bench https://jsonplaceholder.typicode.com/posts -n 100 -c 10
  python api_pulse.py compare https://api.github.com https://api.gitlab.com
  python api_pulse.py chain workflow.json
        """,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── Probe ──
    probe_p = subparsers.add_parser("probe", help="Deep-inspect a single API endpoint")
    probe_p.add_argument("url", help="URL to probe")
    probe_p.add_argument("-m", "--method", default="GET")
    probe_p.add_argument("--html", type=Path, help="Generate HTML report")

    # ── Benchmark ──
    bench_p = subparsers.add_parser("bench", help="Benchmark an endpoint with concurrent requests")
    bench_p.add_argument("url", help="URL to benchmark")
    bench_p.add_argument("-n", "--requests", type=int, default=50, help="Number of requests")
    bench_p.add_argument("-c", "--concurrency", type=int, default=5, help="Concurrent workers")
    bench_p.add_argument("-m", "--method", default="GET")
    bench_p.add_argument("--html", type=Path, help="Generate HTML report")

    # ── Compare ──
    compare_p = subparsers.add_parser("compare", help="Compare multiple endpoints side-by-side")
    compare_p.add_argument("urls", nargs="+", help="URLs to compare")
    compare_p.add_argument("-n", "--requests", type=int, default=30)
    compare_p.add_argument("-c", "--concurrency", type=int, default=5)

    # ── Chain ──
    chain_p = subparsers.add_parser("chain", help="Run a multi-step API workflow from a JSON file")
    chain_p.add_argument("file", type=Path, help="JSON file defining the chain")
    chain_p.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    if args.command == "probe":
        from rich.console import Console
        console = Console()
        with console.status(f"[cyan]Probing {args.url}…[/]"):
            resp = make_request(args.url, args.method)
            tls_info = inspect_tls(args.url)
            audit = audit_security_headers(resp.headers)
        print_probe_report(resp, args.url, tls_info, audit)
        if args.html:
            generate_html_report(args.url, resp, tls_info, audit, None, args.html)

    elif args.command == "bench":
        from rich.console import Console
        console = Console()
        with console.status(f"[cyan]Benchmarking {args.url} ({args.requests} requests, {args.concurrency} workers)…[/]"):
            report = benchmark(args.url, args.method, requests_count=args.requests, concurrency=args.concurrency)
        print_benchmark_report(report)
        if args.html:
            resp = make_request(args.url)
            tls_info = inspect_tls(args.url)
            audit = audit_security_headers(resp.headers)
            generate_html_report(args.url, resp, tls_info, audit, report, args.html)

    elif args.command == "compare":
        from rich.console import Console
        console = Console()
        reports = []
        for url in args.urls:
            with console.status(f"[cyan]Benchmarking {url}…[/]"):
                r = benchmark(url, requests_count=args.requests, concurrency=args.concurrency)
                reports.append(r)
        print_compare_report(reports)

    elif args.command == "chain":
        if not args.file.exists():
            print(f"❌ File not found: {args.file}")
            sys.exit(1)
        chain_data = json.loads(args.file.read_text())
        steps = chain_data if isinstance(chain_data, list) else chain_data.get("steps", [])
        print(f"\n🔗 Running chain: {len(steps)} steps\n")
        results = run_chain(steps, verbose=args.verbose)
        print_chain_report(results)


if __name__ == "__main__":
    main()
