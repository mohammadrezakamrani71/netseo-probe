"""Unit and local-server integration tests for NetSEO-Probe."""

import http.server
import threading
import unittest

from netseo_probe.auditor import audit_offline_html, audit_url
from netseo_probe.reporter import render_html_report, render_json_report, render_markdown_report


SAMPLE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>NetSEO-Probe — Technical SEO &amp; Network Security Test</title>
  <meta name="description" content="A comprehensive test page verifying canonical tags, H1 structure, viewport configuration, and image alt coverage." />
  <link rel="canonical" href="https://example.local/page" />
</head>
<body>
  <h1>Technical SEO &amp; Network Infrastructure</h1>
  <img src="diagram.png" alt="Network Diagram" />
</body>
</html>"""


class _TestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/old":
            self.send_response(301)
            self.send_header("Location", "/final")
            self.end_headers()
            return
        body = SAMPLE_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        pass


class TestNetSeoProbe(unittest.TestCase):
    def test_offline_html_and_headers_audit(self) -> None:
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Encoding": "br",
            "Cache-Control": "public, max-age=3600",
        }
        rep = audit_offline_html(SAMPLE_HTML, "sample.html", headers=headers)
        self.assertEqual(rep.seo_score, 100)
        self.assertEqual(rep.security_score, 100)
        self.assertEqual(rep.network_score, 100)
        self.assertIn("NetSEO-Probe Technical SEO", render_markdown_report(rep))
        self.assertIn("<!DOCTYPE html>", render_html_report(rep))
        self.assertIn('"overall_score": 100', render_json_report(rep))

    def test_live_local_http_redirect_and_ttfb(self) -> None:
        server = http.server.HTTPServer(("127.0.0.1", 0), _TestHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            rep = audit_url(f"http://127.0.0.1:{port}/old", timeout=3.0)
            self.assertEqual(rep.status_code, 200)
            self.assertEqual(rep.redirect_hops, 1)
            self.assertTrue(rep.final_url.endswith("/final"))
            self.assertIsNotNone(rep.ttfb_ms)
            self.assertEqual(rep.seo_score, 100)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
