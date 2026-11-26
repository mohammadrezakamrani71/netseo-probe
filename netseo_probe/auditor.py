"""Orchestrator combining Network/HTTP, Security Headers, and Technical SEO audits."""

from __future__ import annotations

from dataclasses import dataclass, field

from .network import NetworkProbeResult, probe_url
from .security import audit_http_headers
from .seo import CheckItem, audit_html_seo


@dataclass
class FullAuditReport:
    target: str
    final_url: str
    overall_score: int
    network_score: int
    security_score: int
    seo_score: int
    dns_ms: float | None = None
    ttfb_ms: float | None = None
    status_code: int | None = None
    redirect_hops: int = 0
    checks: list[CheckItem] = field(default_factory=list)
    error: str | None = None


def _score_checks(items: list[CheckItem]) -> int:
    if not items:
        return 100
    pts = sum(1.0 if i.status == "PASS" else (0.5 if i.status == "WARN" else 0.0) for i in items)
    return round((pts / len(items)) * 100)


def _evaluate_network_checks(probe: NetworkProbeResult) -> list[CheckItem]:
    checks: list[CheckItem] = []

    if probe.status_code is None:
        checks.append(
            CheckItem("NETWORK", "NET-001", "HTTP Availability", "FAIL", f"Request failed: {probe.error}", "Verify DNS, firewall rules, and origin server availability.")
        )
        return checks

    if 200 <= probe.status_code < 300:
        checks.append(
            CheckItem("NETWORK", "NET-001", "HTTP Status Code", "PASS", f"Returned HTTP {probe.status_code}.", "No action required.")
        )
    else:
        checks.append(
            CheckItem("NETWORK", "NET-001", "HTTP Status Code", "FAIL", f"Returned HTTP {probe.status_code}.", "Investigate server error or unexpected final status code.")
        )

    redirect_count = max(len(probe.redirect_chain) - 1, 0)
    if redirect_count == 0:
        checks.append(
            CheckItem("NETWORK", "NET-002", "Redirect Chain", "PASS", "Direct response (0 redirects).", "No action required.")
        )
    elif redirect_count == 1:
        checks.append(
            CheckItem("NETWORK", "NET-002", "Redirect Chain", "PASS", "Single clean redirect (e.g. HTTP->HTTPS).", "No action required.")
        )
    else:
        checks.append(
            CheckItem("NETWORK", "NET-002", "Redirect Chain", "WARN", f"{redirect_count} redirect hops detected.", "Collapse multi-hop redirect chains to reduce TTFB and preserve crawl budget.")
        )

    if probe.ttfb_ms is not None:
        if probe.ttfb_ms <= 300:
            ttfb_status = "PASS"
            rec = "No action required."
        elif probe.ttfb_ms <= 800:
            ttfb_status = "WARN"
            rec = "Optimize backend response time or add CDN edge caching."
        else:
            ttfb_status = "FAIL"
            rec = "High TTFB (>800ms); investigate origin latency, TLS handshake, or database bottlenecks."
        checks.append(
            CheckItem("NETWORK", "NET-003", "Time to First Byte (TTFB)", ttfb_status, f"TTFB measured at {probe.ttfb_ms:.2f} ms.", rec)
        )

    if probe.final_url.startswith("https://"):
        if probe.tls_version and probe.cert_days_left is not None:
            if probe.cert_days_left < 0:
                tls_st = "FAIL"
            elif probe.cert_days_left <= 30:
                tls_st = "WARN"
            else:
                tls_st = "PASS"
            checks.append(
                CheckItem(
                    "SECURITY",
                    "SEC-000",
                    "HTTPS & TLS Certificate",
                    tls_st,
                    f"{probe.tls_version} | {probe.cert_days_left} days until expiry.",
                    "No action required." if tls_st == "PASS" else "Renew TLS certificate immediately.",
                )
            )
    else:
        checks.append(
            CheckItem("SECURITY", "SEC-000", "HTTPS Enforcement", "FAIL", "Final URL is served over unencrypted HTTP.", "Enable HTTPS and enforce 301 redirect from HTTP to HTTPS.")
        )

    return checks


def audit_url(url: str, timeout: float = 8.0) -> FullAuditReport:
    """Run a full live Network + Security Headers + Technical SEO audit on a URL."""
    probe = probe_url(url, timeout=timeout)
    checks: list[CheckItem] = _evaluate_network_checks(probe)

    if probe.error is None:
        checks.extend(audit_http_headers(probe.headers, is_https=probe.final_url.startswith("https://")))
        if probe.body:
            checks.extend(audit_html_seo(probe.body))

    net_score = _score_checks([c for c in checks if c.category == "NETWORK"])
    sec_score = _score_checks([c for c in checks if c.category == "SECURITY"])
    seo_score = _score_checks([c for c in checks if c.category == "SEO"])
    overall = round((net_score + sec_score + seo_score) / 3)

    return FullAuditReport(
        target=url,
        final_url=probe.final_url,
        overall_score=overall,
        network_score=net_score,
        security_score=sec_score,
        seo_score=seo_score,
        dns_ms=probe.dns_ms,
        ttfb_ms=probe.ttfb_ms,
        status_code=probe.status_code,
        redirect_hops=max(len(probe.redirect_chain) - 1, 0),
        checks=checks,
        error=probe.error,
    )


def audit_offline_html(html_text: str, source_name: str, headers: dict[str, str] | None = None) -> FullAuditReport:
    """Audit a local HTML snapshot (and optional headers) without requiring internet access."""
    checks: list[CheckItem] = []
    if headers:
        checks.extend(audit_http_headers(headers, is_https=True))
    checks.extend(audit_html_seo(html_text))

    net_score = _score_checks([c for c in checks if c.category == "NETWORK"])
    sec_score = _score_checks([c for c in checks if c.category == "SECURITY"])
    seo_score = _score_checks([c for c in checks if c.category == "SEO"])
    overall = _score_checks(checks)

    return FullAuditReport(
        target=source_name,
        final_url=source_name,
        overall_score=overall,
        network_score=net_score,
        security_score=sec_score,
        seo_score=seo_score,
        checks=checks,
    )
