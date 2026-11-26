"""Network & HTTP transport layer diagnostics: DNS timing, TLS inspection, TTFB, and redirect chain tracking."""

from __future__ import annotations

import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class RedirectHop:
    url: str
    status_code: int
    latency_ms: float
    location: str | None = None


@dataclass
class NetworkProbeResult:
    requested_url: str
    final_url: str
    resolved_ips: list[str] = field(default_factory=list)
    dns_ms: float | None = None
    ttfb_ms: float | None = None
    total_ms: float | None = None
    status_code: int | None = None
    tls_version: str | None = None
    cert_days_left: int | None = None
    redirect_chain: list[RedirectHop] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    error: str | None = None


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _measure_dns(hostname: str, timeout: float = 4.0) -> tuple[list[str], float | None]:
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    start = time.perf_counter()
    try:
        infos = socket.getaddrinfo(hostname, None)
        elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)
        ips = sorted({info[4][0] for info in infos})
        return ips, elapsed_ms
    except OSError:
        return [], None
    finally:
        socket.setdefaulttimeout(old_timeout)


def _inspect_tls(hostname: str, port: int = 443, timeout: float = 4.0) -> tuple[str | None, int | None]:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_ver = ssock.version()
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter") if cert else None
                days_left = None
                if not_after:
                    expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=timezone.utc
                    )
                    days_left = (expires_at - datetime.now(timezone.utc)).days
                return tls_ver, days_left
    except OSError:
        return None, None


def probe_url(url: str, max_redirects: int = 8, timeout: float = 8.0) -> NetworkProbeResult:
    """Fetch a URL while tracking DNS latency, redirect hops, TTFB, TLS metadata, and response headers."""
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    ips, dns_ms = _measure_dns(hostname, timeout=min(timeout, 4.0)) if hostname else ([], None)

    opener = urllib.request.build_opener(_NoRedirectHandler())
    current_url = url
    hops: list[RedirectHop] = []
    overall_start = time.perf_counter()
    final_headers: dict[str, str] = {}
    final_status: int | None = None
    body = ""
    ttfb_ms: float | None = None

    for _ in range(max_redirects + 1):
        req = urllib.request.Request(
            current_url,
            headers={
                "User-Agent": "NetSEO-Probe/1.0 (+https://github.com/mohammadrezakamrani71/netseo-probe)",
                "Accept-Encoding": "gzip, br, deflate",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        )
        hop_start = time.perf_counter()
        try:
            with opener.open(req, timeout=timeout) as resp:
                ttfb_ms = round((time.perf_counter() - hop_start) * 1000.0, 2)
                final_status = resp.status
                final_headers = {k.lower(): v for k, v in resp.headers.items()}
                raw_bytes = resp.read(512_000)
                if final_headers.get("content-encoding", "").lower() == "gzip":
                    import gzip
                    try:
                        raw_bytes = gzip.decompress(raw_bytes)
                    except OSError:
                        pass
                body = raw_bytes.decode("utf-8", errors="replace")
                hops.append(RedirectHop(url=current_url, status_code=final_status, latency_ms=ttfb_ms))
                break
        except urllib.error.HTTPError as err:
            hop_ms = round((time.perf_counter() - hop_start) * 1000.0, 2)
            location = err.headers.get("Location") if err.headers else None
            hops.append(RedirectHop(url=current_url, status_code=err.code, latency_ms=hop_ms, location=location))
            if err.code in (301, 302, 303, 307, 308) and location:
                current_url = urllib.parse.urljoin(current_url, location)
                continue
            final_status = err.code
            ttfb_ms = hop_ms
            final_headers = {k.lower(): v for k, v in (err.headers.items() if err.headers else [])}
            break
        except (OSError, urllib.error.URLError) as exc:
            return NetworkProbeResult(
                requested_url=url,
                final_url=current_url,
                resolved_ips=ips,
                dns_ms=dns_ms,
                redirect_chain=hops,
                error=str(exc),
            )

    total_ms = round((time.perf_counter() - overall_start) * 1000.0, 2)
    final_parsed = urllib.parse.urlparse(current_url)
    tls_ver, cert_days = (
        _inspect_tls(final_parsed.hostname, final_parsed.port or 443, timeout=min(timeout, 4.0))
        if final_parsed.scheme == "https" and final_parsed.hostname
        else (None, None)
    )

    return NetworkProbeResult(
        requested_url=url,
        final_url=current_url,
        resolved_ips=ips,
        dns_ms=dns_ms,
        ttfb_ms=ttfb_ms,
        total_ms=total_ms,
        status_code=final_status,
        tls_version=tls_ver,
        cert_days_left=cert_days,
        redirect_chain=hops,
        headers=final_headers,
        body=body,
    )
