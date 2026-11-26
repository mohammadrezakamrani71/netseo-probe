"""HTTP Security & Performance Headers auditor (OWASP & Network Optimization)."""

from __future__ import annotations

from .seo import CheckItem


def audit_http_headers(headers: dict[str, str], is_https: bool = True) -> list[CheckItem]:
    """Audit HTTP response headers for security hardening and transfer optimization."""
    h = {k.lower(): v for k, v in headers.items()}
    checks: list[CheckItem] = []

    # 1. HSTS
    if is_https:
        hsts = h.get("strict-transport-security", "")
        if hsts:
            checks.append(
                CheckItem("SECURITY", "SEC-001", "HSTS (Strict-Transport-Security)", "PASS", f"Enabled (`{hsts}`).", "No action required.")
            )
        else:
            checks.append(
                CheckItem("SECURITY", "SEC-001", "HSTS (Strict-Transport-Security)", "FAIL", "Missing HSTS header on HTTPS response.", "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.")
            )

    # 2. Content-Security-Policy
    if "content-security-policy" in h:
        checks.append(
            CheckItem("SECURITY", "SEC-002", "Content-Security-Policy (CSP)", "PASS", "CSP header present.", "No action required.")
        )
    else:
        checks.append(
            CheckItem("SECURITY", "SEC-002", "Content-Security-Policy (CSP)", "WARN", "CSP header missing.", "Define a Content-Security-Policy to mitigate XSS and injection attacks.")
        )

    # 3. X-Content-Type-Options
    if h.get("x-content-type-options", "").lower() == "nosniff":
        checks.append(
            CheckItem("SECURITY", "SEC-003", "X-Content-Type-Options", "PASS", "`nosniff` enabled.", "No action required.")
        )
    else:
        checks.append(
            CheckItem("SECURITY", "SEC-003", "X-Content-Type-Options", "FAIL", "Missing `nosniff` protection.", "Set `X-Content-Type-Options: nosniff`.")
        )

    # 4. Clickjacking protection
    if "x-frame-options" in h or "frame-ancestors" in h.get("content-security-policy", "").lower():
        checks.append(
            CheckItem("SECURITY", "SEC-004", "Clickjacking Protection", "PASS", "X-Frame-Options or CSP frame-ancestors present.", "No action required.")
        )
    else:
        checks.append(
            CheckItem("SECURITY", "SEC-004", "Clickjacking Protection", "WARN", "Neither X-Frame-Options nor CSP frame-ancestors detected.", "Add `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`.")
        )

    # 5. Compression (Network Efficiency)
    encoding = h.get("content-encoding", "").lower()
    if any(alg in encoding for alg in ("br", "gzip", "zstd")):
        checks.append(
            CheckItem("NETWORK", "NET-004", "HTTP Compression", "PASS", f"Response compressed with `{encoding}`.", "No action required.")
        )
    else:
        checks.append(
            CheckItem("NETWORK", "NET-004", "HTTP Compression", "WARN", "No gzip/brotli compression detected.", "Enable Brotli (`br`) or Gzip compression on your web server/CDN.")
        )

    # 6. Cache-Control
    if "cache-control" in h:
        checks.append(
            CheckItem("NETWORK", "NET-005", "Cache-Control Policy", "PASS", f"Configured (`{h['cache-control']}`).", "No action required.")
        )
    else:
        checks.append(
            CheckItem("NETWORK", "NET-005", "Cache-Control Policy", "WARN", "Missing `Cache-Control` header.", "Configure explicit `Cache-Control` directives for edge/browser caching.")
        )

    return checks
