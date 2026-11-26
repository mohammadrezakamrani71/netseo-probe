"""Command-line interface for NetSEO-Probe."""

from __future__ import annotations

import argparse
from pathlib import Path

from .auditor import audit_offline_html, audit_url
from .reporter import render_html_report, render_json_report, render_markdown_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="netseo-probe",
        description="Technical SEO, HTTP Security Headers & Network Infrastructure Auditor",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="Live HTTP/HTTPS URL to audit")
    group.add_argument("--html-file", type=Path, help="Local HTML snapshot file for offline SEO audit")
    parser.add_argument("--timeout", type=float, default=8.0, help="HTTP/TLS timeout in seconds (default: 8)")
    parser.add_argument("--out-md", type=Path, help="Optional Markdown report output path")
    parser.add_argument("--out-html", type=Path, help="Optional HTML report output path")
    parser.add_argument("--out-json", type=Path, help="Optional JSON report output path")
    args = parser.parse_args(argv)

    if args.url:
        report = audit_url(args.url, timeout=args.timeout)
    else:
        html_text = args.html_file.read_text(encoding="utf-8")
        report = audit_offline_html(html_text, source_name=args.html_file.name)

    md = render_markdown_report(report)
    print(md)

    if args.out_md:
        args.out_md.write_text(md, encoding="utf-8")
    if args.out_html:
        args.out_html.write_text(render_html_report(report), encoding="utf-8")
    if args.out_json:
        args.out_json.write_text(render_json_report(report), encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
