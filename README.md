# NetSEO-Probe — Technical SEO, HTTP Security Headers & Network Infrastructure Auditor

**NetSEO-Probe** bridges **network engineering** and **Technical SEO** in a single zero-dependency Python 3.10+ CLI tool. It audits a website across three critical layers—**Network/HTTP Transport**, **OWASP HTTP Security Headers**, and **On-Page Technical SEO**—and outputs executive **Markdown**, **HTML**, and **JSON** reports.

## Key Features

- **Network & HTTP Transport Layer (`netseo_probe/network.py`)**
  - Measures forward **DNS lookup latency** and resolved IPs.
  - Tracks full **HTTP redirect chains** (`301`/`302`/`307`/`308`) and flags multi-hop chains that waste crawl budget.
  - Measures **Time to First Byte (TTFB)** and total fetch time.
  - Inspects active **TLS protocol version** and **certificate expiration** days remaining.
- **HTTP Security & Efficiency Headers (`netseo_probe/security.py`)**
  - Audits `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Content-Type-Options: nosniff`, and Clickjacking (`X-Frame-Options` / `frame-ancestors`).
  - Verifies **Brotli/Gzip compression** and **Cache-Control** policies.
- **On-Page Technical SEO (`netseo_probe/seo.py`)**
  - Pure-Python HTML parser auditing `<title>` length, `<meta name="description">`, `rel="canonical"`, single `<h1>` hierarchy, `noindex` traps, responsive `viewport`, and image `alt` coverage.
- **Online & Offline Modes:** Supports live `--url` probing as well as air-gapped `--html-file` audits.

## Project Structure

```text
netseo-probe/
├── main.py
├── netseo_probe/
│   ├── __init__.py
│   ├── auditor.py
│   ├── cli.py
│   ├── network.py
│   ├── reporter.py
│   ├── security.py
│   └── seo.py
├── samples/
│   └── sample_page.html
├── tests/
│   └── test_netseo_probe.py
├── LICENSE
└── README.md
```

## Quick Start

Requires **Python 3.10+** (zero external dependencies).

Audit a live website:

```bash
python3 main.py \
  --url https://example.com \
  --out-md report.md \
  --out-html report.html \
  --out-json report.json
```

Audit a local HTML snapshot (offline mode):

```bash
python3 main.py --html-file samples/sample_page.html --out-html offline_report.html
```

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
