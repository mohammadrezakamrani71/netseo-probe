"""Markdown, JSON, and executive HTML report generator for NetSEO-Probe."""

from __future__ import annotations

import html
import json
from dataclasses import asdict
from datetime import datetime, timezone

from .auditor import FullAuditReport


def render_json_report(report: FullAuditReport) -> str:
    return json.dumps(asdict(report), indent=2)


def render_markdown_report(report: FullAuditReport) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# NetSEO-Probe Technical SEO & Network Audit Report",
        "",
        f"**Generated:** {timestamp}  ",
        f"**Target:** `{report.target}`  ",
        f"**Final URL:** `{report.final_url}`  ",
        f"**Overall Score:** **{report.overall_score}%** (Network: {report.network_score}% | Security: {report.security_score}% | SEO: {report.seo_score}%)",
        "",
        "| Category | Rule | Check | Status | Detail | Recommendation |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for c in report.checks:
        lines.append(
            f"| {c.category} | `{c.rule_id}` | {c.title} | **{c.status}** | {c.detail} | {c.recommendation} |"
        )
    lines.append("")
    return "\n".join(lines)


def render_html_report(report: FullAuditReport) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def badge(status: str) -> str:
        colors = {"PASS": "#16a34a", "WARN": "#d97706", "FAIL": "#dc2626"}
        bg = colors.get(status, "#475569")
        return f'<span style="background:{bg};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600;">{html.escape(status)}</span>'

    rows = "\n".join(
        f"<tr><td><strong>{html.escape(c.category)}</strong></td><td><code>{html.escape(c.rule_id)}</code></td>"
        f"<td>{html.escape(c.title)}</td><td>{badge(c.status)}</td>"
        f"<td>{html.escape(c.detail)}</td><td>{html.escape(c.recommendation)}</td></tr>"
        for c in report.checks
    )

    ttfb_str = f"{report.ttfb_ms:.1f} ms" if report.ttfb_ms is not None else "N/A"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NetSEO-Probe Audit Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 32px; background: #0f172a; color: #e2e8f0; }}
  .container {{ max-width: 1140px; margin: 0 auto; background: #1e293b; padding: 28px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }}
  h1 {{ margin-top: 0; font-size: 24px; color: #f8fafc; }}
  .meta {{ color: #94a3b8; font-size: 14px; margin-bottom: 20px; }}
  .kpis {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 14px; margin-bottom: 24px; }}
  .kpi {{ background: #0f172a; padding: 14px 16px; border-radius: 8px; border: 1px solid #334155; }}
  .kpi span {{ font-size: 12px; color: #94a3b8; display: block; }}
  .kpi strong {{ font-size: 22px; color: #38bdf8; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #334155; vertical-align: top; }}
  th {{ background: #0f172a; color: #cbd5e1; font-weight: 600; }}
  code {{ background: #0f172a; color: #7dd3fc; padding: 2px 5px; border-radius: 4px; font-size: 13px; }}
</style>
</head>
<body>
<div class="container">
  <h1>NetSEO-Probe Technical SEO &amp; Network Audit</h1>
  <div class="meta">Generated: {html.escape(timestamp)} | Target: <code>{html.escape(report.target)}</code></div>
  <div class="kpis">
    <div class="kpi"><span>Overall Score</span><strong>{report.overall_score}%</strong></div>
    <div class="kpi"><span>Network / HTTP</span><strong>{report.network_score}%</strong></div>
    <div class="kpi"><span>Security Headers</span><strong>{report.security_score}%</strong></div>
    <div class="kpi"><span>Technical SEO</span><strong>{report.seo_score}%</strong></div>
    <div class="kpi"><span>TTFB</span><strong>{html.escape(ttfb_str)}</strong></div>
  </div>
  <table>
    <thead><tr><th>Layer</th><th>Rule</th><th>Control</th><th>Status</th><th>Finding</th><th>Recommendation</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>
</body>
</html>
"""
