#!/usr/bin/env python3
"""Tests for puppet_enterprise_scanner.py. Run: python3 -m pytest tests/ -q
or: python3 tests/test_puppet_enterprise_scanner.py (runs unittest)."""

import io
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import puppet_enterprise_scanner as s


class TestParseVersion(unittest.TestCase):
    def test_bare_pe(self):
        self.assertEqual(s.parse_version("2025.12.1"), (2025, 12, 1))

    def test_bare_two_part(self):
        self.assertEqual(s.parse_version("9.2"), (9, 2))

    def test_package_name(self):
        self.assertEqual(
            s.parse_version("openvox-server-9.1.1-1.el9.x86_64"),
            (9, 1, 1))

    def test_command_output(self):
        self.assertEqual(
            s.parse_version("puppetserver version: 8.10.0\n"),
            (8, 10, 0))

    def test_version_file(self):
        self.assertEqual(s.parse_version("8.22.1\n"), (8, 22, 1))

    def test_junk_is_none(self):
        self.assertIsNone(s.parse_version("no version here"))


class TestGradePE(unittest.TestCase):
    def test_2023_line(self):
        self.assertEqual(s.grade_pe((2023, 8, 12))[0], "VULNERABLE")
        self.assertEqual(s.grade_pe((2023, 8, 13))[0], "PATCHED")
        self.assertEqual(s.grade_pe((2023, 8, 14))[0], "PATCHED")

    def test_2025_line(self):
        self.assertEqual(s.grade_pe((2025, 12, 0))[0], "VULNERABLE")
        self.assertEqual(s.grade_pe((2025, 12, 1))[0], "PATCHED")
        self.assertEqual(s.grade_pe((2025, 5, 0))[0], "VULNERABLE")
        self.assertEqual(s.grade_pe((2025, 0, 0))[0], "VULNERABLE")

    def test_2026_line(self):
        self.assertEqual(s.grade_pe((2026, 0, 0))[0], "VULNERABLE")
        self.assertEqual(s.grade_pe((2026, 0, 1))[0], "PATCHED")

    def test_bare_versions_unknown(self):
        self.assertEqual(s.grade_pe((2025, 12))[0], "UNKNOWN")
        self.assertEqual(s.grade_pe((2023, 8))[0], "UNKNOWN")
        self.assertEqual(s.grade_pe((2025,))[0], "UNKNOWN")

    def test_pre_2023_vulnerable(self):
        # Bug confirmed back to Puppet 6.24.0 (2021); no fix on old lines.
        self.assertEqual(s.grade_pe((2021, 7, 0))[0], "VULNERABLE")

    def test_unknown_line(self):
        self.assertEqual(s.grade_pe((2023, 9, 0))[0], "UNKNOWN")
        self.assertEqual(s.grade_pe((2027, 1, 0))[0], "UNKNOWN")


class TestGradeOpenVox(unittest.TestCase):
    def test_server_9x(self):
        self.assertEqual(
            s.grade_version("openvox-server", (9, 1, 1))[0], "VULNERABLE")
        self.assertEqual(
            s.grade_version("openvox-server", (9, 2, 0))[0], "PATCHED")

    def test_server_8x(self):
        self.assertEqual(
            s.grade_version("openvox-server", (8, 17, 1))[0], "VULNERABLE")
        self.assertEqual(
            s.grade_version("openvox-server", (8, 18, 0))[0], "PATCHED")

    def test_agent_shipped_after_disclosure_still_vulnerable(self):
        # 9.2.1 / 8.31.2 shipped 23/29 Oct, before the fix landed.
        self.assertEqual(
            s.grade_version("openvox-agent", (9, 2, 1))[0], "VULNERABLE")
        self.assertEqual(
            s.grade_version("openvox-agent", (8, 31, 2))[0], "VULNERABLE")
        self.assertEqual(
            s.grade_version("openvox-agent", (9, 3, 0))[0], "PATCHED")
        self.assertEqual(
            s.grade_version("openvox-agent", (8, 32, 0))[0], "PATCHED")

    def test_openvoxdb(self):
        self.assertEqual(
            s.grade_version("openvoxdb", (9, 1, 0))[0], "VULNERABLE")
        self.assertEqual(
            s.grade_version("openvoxdb", (9, 2, 0))[0], "PATCHED")


class TestGradePuppetCoreAndOpenSource(unittest.TestCase):
    def test_puppet_core(self):
        self.assertEqual(
            s.grade_version("puppet-core", (9, 1, 2))[0], "VULNERABLE")
        self.assertEqual(
            s.grade_version("puppet-core", (9, 1, 3))[0], "PATCHED")
        self.assertEqual(
            s.grade_version("puppet-core", (8, 22, 0))[0], "VULNERABLE")
        self.assertEqual(
            s.grade_version("puppet-core", (8, 22, 1))[0], "PATCHED")
        self.assertEqual(
            s.grade_version("puppet-core", (7, 0, 0))[0], "VULNERABLE")

    def test_open_source_no_fix(self):
        # Fully up-to-date community Puppet is still vulnerable: no
        # fixed release exists on that line at any version.
        self.assertEqual(
            s.grade_version("puppet", (8, 10, 0))[0], "VULNERABLE")
        self.assertEqual(
            s.grade_version("puppetserver", (8, 10, 0))[0], "VULNERABLE")
        verdict, reason = s.grade_version("puppet", (8, 10, 0))
        self.assertIn("NO fixed release", reason)

    def test_trapperkeeper(self):
        self.assertEqual(
            s.grade_version("trapperkeeper-authorization", (2, 4, 1))[0],
            "VULNERABLE")
        self.assertEqual(
            s.grade_version("trapperkeeper-authorization", (2, 5, 0))[0],
            "PATCHED")


class TestCertCN(unittest.TestCase):
    def test_cn_extraction(self):
        # Build a throwaway cert with openssl and read its CNs back.
        with tempfile.TemporaryDirectory() as tmp:
            key = os.path.join(tmp, "key.pem")
            crt = os.path.join(tmp, "crt.pem")
            try:
                subprocess.run(
                    ["openssl", "req", "-x509", "-newkey", "rsa:2048",
                     "-keyout", key, "-out", crt, "-days", "1",
                     "-nodes", "-subj",
                     "/CN=puppet.example.com/O=Puppet CA"],
                    check=True, capture_output=True)
            except (OSError, subprocess.CalledProcessError):
                self.skipTest("openssl unavailable")
            with open(crt, "r") as fh:
                pem = fh.read()
            der = ssl.PEM_cert_to_DER_cert(pem)
            cns = s.cert_common_names(der)
            self.assertIn("puppet.example.com", cns)


class TestProbeHost(unittest.TestCase):
    def _start_tls_server(self, certfile, keyfile):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"message":"Forbidden"}'
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        httpd = HTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        return httpd

    def test_probe_tls_403(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = os.path.join(tmp, "key.pem")
            crt = os.path.join(tmp, "crt.pem")
            try:
                subprocess.run(
                    ["openssl", "req", "-x509", "-newkey", "rsa:2048",
                     "-keyout", key, "-out", crt, "-days", "1",
                     "-nodes", "-subj", "/CN=puppet.example.com"],
                    check=True, capture_output=True)
            except (OSError, subprocess.CalledProcessError):
                self.skipTest("openssl unavailable")
            httpd = self._start_tls_server(crt, key)
            try:
                port = httpd.server_address[1]
                result = s.probe_host("127.0.0.1", port=port)
            finally:
                httpd.shutdown()
            self.assertTrue(result["reachable"])
            self.assertTrue(result["tls"])
            self.assertEqual(result["status_code"], 403)
            self.assertEqual(result["verdict"], "UNKNOWN")
            self.assertIn("puppet.example.com", result["cert_cns"])

    def test_probe_closed_port(self):
        # Bind a socket, close it, probe the (now free) port.
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        result = s.probe_host("127.0.0.1", port=port, timeout=3)
        self.assertFalse(result["reachable"])
        self.assertEqual(result["verdict"], "UNKNOWN")


class TestScanLogs(unittest.TestCase):
    BENIGN_REPORT = json.dumps({
        "host": "web01.example.com",
        "resource_statuses": {
            "File[/etc/motd]": {
                "events": [{"property": "content",
                            "previous_value": "old",
                            "desired_value": "new"}]
            }
        },
    })

    MALICIOUS_REPORT = json.dumps({
        "host": "web01.example.com",
        "resource_statuses": {
            "File[/etc/motd]": {
                "events": [{
                    "__ptype": "Object[{name => 'PEP', functions => "
                               "{'test' => {type => Callable, annotations "
                               "=> {RubyMethod => {'body' => \"1\"}}}}}]",
                    "__pvalue": "x"}]
            }
        },
    })

    ACCESS_LOG = (
        '10.0.0.5 - - [17/Nov/2026:10:00:00 +0000] '
        '"PUT /puppet/v3/report/web01.example.com?environment=production '
        'HTTP/1.1" 200 1234\n'
        '10.0.0.9 - - [17/Nov/2026:10:01:00 +0000] '
        '"PUT /puppet/v3/report/evil.web01.example.com?environment=production '
        'HTTP/1.1" 200 1234\n'
    )

    def test_benign_report_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.json")
            with open(path, "w") as fh:
                fh.write(self.BENIGN_REPORT)
            hits, certnames, scanned = s.scan_logs([tmp])
            self.assertEqual(hits, [])
            self.assertEqual(scanned, 1)

    def test_malicious_report_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.json")
            with open(path, "w") as fh:
                fh.write(self.MALICIOUS_REPORT)
            hits, certnames, scanned = s.scan_logs([tmp])
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0][0], path)

    def test_access_log_certnames_and_impersonation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "access.log")
            with open(path, "w") as fh:
                fh.write(self.ACCESS_LOG)
            hits, certnames, scanned = s.scan_logs([tmp])
            self.assertEqual(hits, [])
            self.assertEqual(certnames,
                             ["evil.web01.example.com",
                              "web01.example.com"])
            flagged = s.find_prefix_impersonation(certnames)
            self.assertEqual(flagged,
                             [("evil.web01.example.com",
                               "web01.example.com")])

    def test_gz_log(self):
        import gzip
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.json.gz")
            with gzip.open(path, "wt") as fh:
                fh.write(self.MALICIOUS_REPORT)
            hits, _, scanned = s.scan_logs([tmp])
            self.assertEqual(len(hits), 1)
            self.assertEqual(scanned, 1)


class TestCLI(unittest.TestCase):
    def _run_main(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = s.main(argv)
        return code, buf.getvalue()

    def test_list(self):
        code, out = self._run_main(["--list"])
        self.assertEqual(code, 0)
        self.assertIn("2023.8.13", out)
        self.assertIn("2025.12.1", out)
        self.assertIn("9.2.0", out)

    def test_pe_vulnerable(self):
        code, out = self._run_main(
            ["--product", "pe", "--version", "2025.12.0"])
        self.assertEqual(code, 1)
        self.assertIn("verdict: VULNERABLE", out)

    def test_pe_patched(self):
        code, out = self._run_main(
            ["--product", "pe", "--version", "2025.12.1"])
        self.assertEqual(code, 0)
        self.assertIn("verdict: PATCHED", out)

    def test_open_source_no_fix(self):
        code, out = self._run_main(
            ["--product", "puppet", "--version", "8.10.0"])
        self.assertEqual(code, 1)
        self.assertIn("verdict: VULNERABLE", out)

    def test_json_output(self):
        code, out = self._run_main(
            ["--product", "pe", "--version", "2023.8.13", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["verdict"], "PATCHED")

    def test_logs_suspicious(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.json")
            with open(path, "w") as fh:
                fh.write(TestScanLogs.MALICIOUS_REPORT)
            code, out = self._run_main(["--logs", tmp])
            self.assertEqual(code, 1)
            self.assertIn("verdict: SUSPICIOUS", out)

    def test_logs_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.json")
            with open(path, "w") as fh:
                fh.write(TestScanLogs.BENIGN_REPORT)
            code, out = self._run_main(["--logs", tmp])
            self.assertEqual(code, 0)
            self.assertIn("verdict: CLEAN", out)

    def test_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "fleet.json")
            with open(path, "w") as fh:
                json.dump([
                    {"host": "pe-a", "product": "pe",
                     "version": "2025.12.1"},
                    {"host": "pe-b", "product": "pe",
                     "version": "2023.8.12"},
                ], fh)
            code, out = self._run_main(["--inventory-json", path])
            self.assertEqual(code, 1)
            self.assertIn("PATCHED", out)
            self.assertIn("VULNERABLE", out)

    def test_no_args_usage_error(self):
        code, out = self._run_main([])
        self.assertEqual(code, 3)


if __name__ == "__main__":
    unittest.main()
