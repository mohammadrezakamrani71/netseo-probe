"""Zero-dependency HTML technical SEO parser and auditor."""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser


@dataclass
class CheckItem:
    category: str  # "NETWORK" | "SECURITY" | "SEO"
    rule_id: str
    title: str
    status: str    # "PASS" | "WARN" | "FAIL"
    detail: str
    recommendation: str


class _SeoHtmlParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_title = False
        self.in_h1 = False
        self.title_parts: list[str] = []
        self.h1_list: list[str] = []
        self._current_h1: list[str] = []
        self.meta: dict[str, str] = {}
        self.canonical: str | None = None
        self.lang: str | None = None
        self.img_total = 0
        self.img_with_alt = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        attr_map = {k.lower(): (v or "") for k, v in attrs}

        if t == "html" and "lang" in attr_map:
            self.lang = attr_map["lang"].strip()
        elif t == "title":
            self.in_title = True
        elif t == "h1":
            self.in_h1 = True
            self._current_h1 = []
        elif t == "meta":
            name = (attr_map.get("name") or attr_map.get("property") or "").lower().strip()
            content = attr_map.get("content", "").strip()
            if name:
                self.meta[name] = content
        elif t == "link":
            rel = attr_map.get("rel", "").lower()
            if "canonical" in rel.split():
                self.canonical = attr_map.get("href", "").strip()
        elif t == "img":
            self.img_total += 1
            if attr_map.get("alt", "").strip():
                self.img_with_alt += 1

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t == "title":
            self.in_title = False
        elif t == "h1" and self.in_h1:
            self.in_h1 = False
            text = " ".join("".join(self._current_h1).split())
            if text:
                self.h1_list.append(text)

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)
        if self.in_h1:
            self._current_h1.append(data)


def audit_html_seo(html_text: str) -> list[CheckItem]:
    """Audit on-page Technical SEO elements from raw HTML."""
    parser = _SeoHtmlParser()
    parser.feed(html_text)
    checks: list[CheckItem] = []

    title = " ".join("".join(parser.title_parts).split())
    if not title:
        checks.append(
            CheckItem("SEO", "SEO-001", "Title Tag", "FAIL", "Missing <title> tag.", "Add a unique 30–60 character <title>.")
        )
    elif 30 <= len(title) <= 65:
        checks.append(
            CheckItem("SEO", "SEO-001", "Title Tag", "PASS", f"Optimal length ({len(title)} chars): '{title}'", "No action required.")
        )
    else:
        checks.append(
            CheckItem("SEO", "SEO-001", "Title Tag", "WARN", f"Length is {len(title)} chars (recommended 30–65).", "Refine <title> length for SERP display.")
        )

    desc = parser.meta.get("description", "")
    if not desc:
        checks.append(
            CheckItem("SEO", "SEO-002", "Meta Description", "FAIL", "Missing meta description.", "Add a concise 120–160 char meta description.")
        )
    elif 70 <= len(desc) <= 165:
        checks.append(
            CheckItem("SEO", "SEO-002", "Meta Description", "PASS", f"Optimal length ({len(desc)} chars).", "No action required.")
        )
    else:
        checks.append(
            CheckItem("SEO", "SEO-002", "Meta Description", "WARN", f"Length is {len(desc)} chars (recommended 70–165).", "Adjust meta description to prevent truncation.")
        )

    if parser.canonical:
        checks.append(
            CheckItem("SEO", "SEO-003", "Canonical URL", "PASS", f"Canonical set to `{parser.canonical}`.", "No action required.")
        )
    else:
        checks.append(
            CheckItem("SEO", "SEO-003", "Canonical URL", "WARN", "No rel='canonical' link tag found.", "Add <link rel=\"canonical\" href=\"...\"> to prevent duplicate indexing.")
        )

    if len(parser.h1_list) == 1:
        checks.append(
            CheckItem("SEO", "SEO-004", "H1 Heading Structure", "PASS", f"Single H1 found: '{parser.h1_list[0]}'", "No action required.")
        )
    elif len(parser.h1_list) == 0:
        checks.append(
            CheckItem("SEO", "SEO-004", "H1 Heading Structure", "FAIL", "No <h1> heading found.", "Add one primary <h1> describing the page topic.")
        )
    else:
        checks.append(
            CheckItem("SEO", "SEO-004", "H1 Heading Structure", "WARN", f"Multiple H1 tags found ({len(parser.h1_list)}).", "Use a single primary <h1> and <h2>/<h3> for subsections.")
        )

    robots = parser.meta.get("robots", "").lower()
    if "noindex" in robots:
        checks.append(
            CheckItem("SEO", "SEO-005", "Indexability (Meta Robots)", "WARN", f"Page has `noindex` directive (`{robots}`).", "Remove `noindex` if the page should appear in search engines.")
        )
    else:
        checks.append(
            CheckItem("SEO", "SEO-005", "Indexability (Meta Robots)", "PASS", "Page is indexable (no `noindex` directive).", "No action required.")
        )

    if "viewport" in parser.meta:
        checks.append(
            CheckItem("SEO", "SEO-006", "Mobile Viewport", "PASS", f"Viewport configured (`{parser.meta['viewport']}`).", "No action required.")
        )
    else:
        checks.append(
            CheckItem("SEO", "SEO-006", "Mobile Viewport", "FAIL", "Missing responsive viewport meta tag.", "Add `<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">`.")
        )

    if parser.img_total > 0:
        pct = round((parser.img_with_alt / parser.img_total) * 100)
        status = "PASS" if pct == 100 else ("WARN" if pct >= 70 else "FAIL")
        checks.append(
            CheckItem(
                "SEO",
                "SEO-007",
                "Image Alt Attributes",
                status,
                f"{parser.img_with_alt}/{parser.img_total} images have alt text ({pct}%).",
                "No action required." if status == "PASS" else "Add descriptive `alt` attributes to all meaningful images.",
            )
        )

    return checks
