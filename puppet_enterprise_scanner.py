#!/usr/bin/env python3
"""`puppet-enterprise-scanner` — detection-only triage for Perforce Puppet
Enterprise / OpenVox `CVE-2026-115731` (report deserialization to server
RCE, CVSS 4.0 9.4) and its companion `CVE-2026-115732` (certificate-name
authorization bypass, CVSS 4.0 9.0).

Puppet agents send a JSON report to the server after every run, `PUT
/puppet/v3/report/<certname>`. The server rebuilds each event with Puppet's
rich-data deserializer, which honours a `__ptype` key: it parses the value
as a Puppet type expression and builds an instance of that type. A type
expression can define a new object type inline, and a `RubyMethod`
annotation on one of its functions has its `body` pasted into a generated
class and run through `class_eval`. Ruby executes backticks in a class body
at definition time, so a crafted report runs a shell command as the
`puppet` service user the moment the server parses it. That user can read
the CA signing key, so the attacker can then mint certificates for any
node in the fleet.

The report endpoint needs a client certificate signed by the Puppet CA.
Every managed node already has one, and many fleets autosign new
certificate requests, so in that setup an unauthenticated attacker with
network access to port 8140 can enrol a certificate and then run code on
the server. Neodyme found the bug while preparing a red team engagement
and reported it in October 2026; fixes shipped 2026-11-03. CISA added
`CVE-2026-115731` to the Known Exploited Vulnerabilities catalog on
2026-11-17, due 2026-12-01.

This tool grades an install by its version, probes a live server's port
8140 the way a defender would (one TCP connect, one TLS handshake, one
plain GET that expects a 401/403 — no client certificate, no report, no
payload), and greps saved reports and logs for the exploitation markers
the advisories name. It sends no report body and nothing that could
trigger the flaw.

Fixed versions, per the Perforce advisory and the OpenVox advisories
(all released 2026-11-03):

    Puppet Enterprise  2023.8.13 / 2025.12.1 / 2026.0.1
    Puppet Core        9.1.3 / 8.22.1
    OpenVox Server     9.2.0 / 8.18.0
    OpenVox agent      9.3.0 / 8.32.0  (the agent is not the vulnerable
                                       part; the server is)
    trapperkeeper-authorization  2.5.0  (CVE-2026-115732 only)

Community open-source Puppet and Puppet Server have NO fix at any
version: Perforce moved Puppet off its open-source licence in 2025 and
Vox Pupuli says the open-source builds will not receive security
updates. Migrate to OpenVox or Puppet Core.

Usage:

    # grade a version string for a named product
    python3 puppet_enterprise_scanner.py --product pe --version "2025.12.0"
    python3 puppet_enterprise_scanner.py --product openvox-server --version "9.1.1"
    python3 puppet_enterprise_scanner.py --product puppet --version "8.10.0"

    # on the Puppet box itself (package list + version commands + autosign)
    python3 puppet_enterprise_scanner.py --local

    # a live server: port 8140 reachability + TLS cert + status probe
    python3 puppet_enterprise_scanner.py --host puppet.example.com
    python3 puppet_enterprise_scanner.py --host puppet.example.com --port 8140

    # hunt saved reports / logs for the exploitation markers
    python3 puppet_enterprise_scanner.py --logs /var/log/puppetlabs/puppetserver/
    python3 puppet_enterprise_scanner.py --reports /opt/puppetlabs/server/data/puppetserver/reports/

    # a whole fleet at once
    python3 puppet_enterprise_scanner.py --inventory-json fleet.json

    # machine output / the fixed-version table
    python3 puppet_enterprise_scanner.py --product pe --version "2025.12.1" --json
    python3 puppet_enterprise_scanner.py --list

Exit codes: 0 patched / not affected / not exposed / clean, 1 vulnerable
or suspicious, 2 unknown, 3 usage error.
"""

import argparse
import gzip
import hashlib
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

CVE_ID = "CVE-2026-115731"
CVE_COMPANION = "CVE-2026-115732"

DEFAULT_PORT = 8140
STATUS_PATH = "/status/v1/simple"
USER_AGENT = "puppet-enterprise-scanner/1.0 (detection-only version check)"

# Products the tool knows how to grade. The `kind` selects the table.
PRODUCTS = (
    "pe",
    "puppet-core",
    "openvox-server",
    "openvox-agent",
    "openvoxdb",
    "puppet",
    "puppetserver",
    "trapperkeeper-authorization",
)

PRODUCT_LABELS = {
    "pe": "Puppet Enterprise",
    "puppet-core": "Puppet Core",
    "openvox-server": "OpenVox Server",
    "openvox-agent": "OpenVox agent",
    "openvoxdb": "OpenVoxDB",
    "puppet": "community open-source Puppet",
    "puppetserver": "community Puppet Server",
    "trapperkeeper-authorization": "trapperkeeper-authorization",
}

# ---------------------------------------------------------------------------
# Version handling
# ---------------------------------------------------------------------------

def parse_version_tuple(text):
    """Parse `2025.12.1`, `9.2.0` or `2025.12` into a tuple of ints."""
    if not text:
        return None
    parts = text.strip().split(".")
    if not all(p.isdigit() for p in parts):
        return None
    if len(parts) > 4:
        return None
    return tuple(int(p) for p in parts)


def parse_version(text):
    """Pull a version out of free text.

    Anchored patterns first (package names, VERSION files, command
    output), then a bare version string, so a stray date or port number
    is not mistaken for a version. Returns a tuple of ints or None.
    """
    if not text:
        return None
    m = re.search(
        r"(?:puppet-enterprise|openvox-server|openvox-agent|openvoxdb|"
        r"puppetserver|puppet-agent|puppet|openvox)[-_ ]"
        r"(\d+\.\d+(?:\.\d+){0,2})", text, re.IGNORECASE)
    if not m:
        m = re.search(r"version\s*[=:]\s*(\d+\.\d+(?:\.\d+){0,2})",
                      text, re.IGNORECASE)
    if not m:
        m = re.search(r"^\s*(\d+\.\d+(?:\.\d+){0,2})\s*$", text)
    if not m:
        return None
    return parse_version_tuple(m.group(1))


def version_string(version):
    if not version:
        return "unknown"
    return ".".join(str(p) for p in version)


def cmp_version(a, b):
    """Compare two version tuples, padding the shorter with zeros."""
    n = max(len(a), len(b))
    aa = a + (0,) * (n - len(a))
    bb = b + (0,) * (n - len(b))
    return (aa > bb) - (aa < bb)


def _line_grade(version, fixed, label, line):
    """Grade `version` against `fixed` on one release line.

    `fixed` is the first fixed release on that line, `line` is the line
    name for messages. Returns (verdict, reason).
    """
    if cmp_version(version, fixed) >= 0:
        return "PATCHED", (
            "%s %s is at or above the fixed release %s (advisory, "
            "2026-11-03)." % (label, version_string(version),
                              version_string(fixed))
        )
    return "VULNERABLE", (
        "%s %s is below the fixed release %s (advisory, 2026-11-03). "
        "Upgrade to %s or later." % (label, version_string(version),
                                     version_string(fixed),
                                     version_string(fixed))
    )


def grade_pe(version):
    """Grade a Puppet Enterprise version. Returns (verdict, reason)."""
    label = "Puppet Enterprise"
    if not version:
        return "UNKNOWN", "no Puppet Enterprise version found in the input"
    if len(version) < 2:
        return "UNKNOWN", (
            "bare major version %s says nothing about the patch level. "
            "The fixes are 2023.8.13, 2025.12.1 and 2026.0.1. Give the "
            "full version, e.g. --version \"2025.12.1\"."
            % version_string(version)
        )
    major, minor = version[0], version[1]
    if major < 2023:
        # The bug is in Puppet code confirmed exploitable back to 6.24.0
        # (July 2021), so any older PE line carries it, and no fix was
        # ever named for those lines.
        return "VULNERABLE", (
            "%s %s predates the earliest affected range the CNA names "
            "(2023.8.0), and the bug is confirmed back to Puppet 6.24.0 "
            "(2021). No fix exists on this line: upgrade to a supported "
            "line at 2023.8.13, 2025.12.1 or 2026.0.1."
            % (label, version_string(version))
        )
    if major == 2023:
        if minor != 8:
            return "UNKNOWN", (
                "%s %s is not in the advisory's fixed-version table, "
                "which names only the 2023.8 line (fixed 2023.8.13). "
                "Do not assume it is clean; check the advisory for "
                "your line." % (label, version_string(version))
            )
        if len(version) < 3:
            return "UNKNOWN", (
                "bare 2023.8 says nothing about the patch level: "
                "2023.8.0 through 2023.8.12 are vulnerable and the fix "
                "is 2023.8.13. Give the full version."
            )
        return _line_grade(version, (2023, 8, 13), label, "2023.8")
    if major == 2025:
        if len(version) < 3:
            return "UNKNOWN", (
                "bare 2025.%d says nothing about the patch level. The "
                "fix is 2025.12.1, and every 2025 release before it is "
                "vulnerable. Give the full version, e.g. --version "
                "\"2025.12.1\"." % minor
            )
        return _line_grade(version, (2025, 12, 1), label, "2025")
    if major == 2026:
        if minor != 0:
            return "UNKNOWN", (
                "%s %s is not in the advisory's fixed-version table, "
                "which names only the 2026.0 line (fixed 2026.0.1). "
                "Do not assume it is clean; check the advisory for "
                "your line." % (label, version_string(version))
            )
        if len(version) < 3:
            return "UNKNOWN", (
                "bare 2026.0 says nothing about the patch level: "
                "2026.0.0 is vulnerable and the fix is 2026.0.1. Give "
                "the full version."
            )
        return _line_grade(version, (2026, 0, 1), label, "2026.0")
    return "UNKNOWN", (
        "%s %s is newer than the advisory's fixed-version table "
        "(2023.8.13, 2025.12.1, 2026.0.1). Do not assume it is clean; "
        "check the advisory for your line." % (label,
                                               version_string(version))
    )


def grade_two_line(version, fixed_9x, fixed_8x, label, fixed_note=""):
    """Grade a 9.x / 8.x product. `fixed_9x` / `fixed_8x` are the first
    fixed releases on each line. Returns (verdict, reason)."""
    if not version:
        return "UNKNOWN", "no %s version found in the input" % label
    if len(version) < 2:
        return "UNKNOWN", (
            "bare major version %s says nothing about the patch level. "
            "The fixes are %s and %s. Give the full version."
            % (version_string(version), version_string(fixed_9x),
               version_string(fixed_8x))
        )
    major = version[0]
    if major == 9:
        if len(version) < 3:
            return "UNKNOWN", (
                "bare 9.%d says nothing about the patch level. Give the "
                "full version, e.g. --version \"%s\"."
                % (version[1], version_string(fixed_9x))
            )
        verdict, reason = _line_grade(version, fixed_9x, label, "9.x")
        return verdict, reason + fixed_note
    if major == 8:
        if len(version) < 3:
            return "UNKNOWN", (
                "bare 8.%d says nothing about the patch level. Give the "
                "full version, e.g. --version \"%s\"."
                % (version[1], version_string(fixed_8x))
            )
        verdict, reason = _line_grade(version, fixed_8x, label, "8.x")
        return verdict, reason + fixed_note
    if major < 8:
        # The bug is confirmed back to Puppet 6.24.0 (2021); older
        # lines carry it and never got a fix.
        return "VULNERABLE", (
            "%s %s predates the 8.x line, and the bug is confirmed back "
            "to Puppet 6.24.0 (2021). No fix exists on this line: "
            "upgrade to %s or %s." % (label, version_string(version),
                                      version_string(fixed_9x),
                                      version_string(fixed_8x))
        )
    return "UNKNOWN", (
        "%s %s is newer than the advisory's fixed-version table (%s, "
        "%s). Do not assume it is clean; check the advisory for your "
        "line." % (label, version_string(version),
                   version_string(fixed_9x), version_string(fixed_8x))
    )


def grade_open_source(version, label):
    """Community Puppet / Puppet Server: no fix exists at any version."""
    if not version:
        return "UNKNOWN", "no %s version found in the input" % label
    return "VULNERABLE", (
        "%s %s is community open-source Puppet, which has NO fixed "
        "release for %s at any version (Perforce moved Puppet off its "
        "open-source licence in 2025; Vox Pupuli says the open-source "
        "builds will not receive security updates). Migrate to OpenVox "
        "(server 9.2.0 / 8.18.0) or Puppet Core (9.1.3 / 8.22.1)."
        % (label, version_string(version), CVE_ID)
    )


def grade_trapperkeeper(version):
    """trapperkeeper-authorization, the CVE-2026-115732 component."""
    label = "trapperkeeper-authorization"
    if not version:
        return "UNKNOWN", "no %s version found in the input" % label
    if cmp_version(version, (2, 5, 0)) >= 0:
        return "PATCHED", (
            "%s %s is at or above the fixed release 2.5.0, which gives "
            "wildcards their own match type and makes exact rules "
            "compare the full certname (%s fix, 2026-11-03)."
            % (label, version_string(version), CVE_COMPANION)
        )
    return "VULNERABLE", (
        "%s %s is below the fixed release 2.5.0. Exact certname rules "
        "match like prefix wildcards, so a certificate for "
        "evil.target.example.com passes a rule written for "
        "target.example.com (%s). Upgrade to 2.5.0 or later."
        % (label, version_string(version), CVE_COMPANION)
    )


def grade_version(product, version):
    """Grade `version` for `product`. Returns (verdict, reason)."""
    label = PRODUCT_LABELS[product]
    if product == "pe":
        return grade_pe(version)
    if product == "puppet-core":
        return grade_two_line(version, (9, 1, 3), (8, 22, 1), label)
    if product == "openvox-server":
        return grade_two_line(version, (9, 2, 0), (8, 18, 0), label)
    if product == "openvox-agent":
        note = (" The agent is not the vulnerable part — the server "
                "is. Patch the server (OpenVox Server 9.2.0 / 8.18.0) "
                "first; the agent fix matters for report handling on "
                "hosts that also run a server.")
        return grade_two_line(version, (9, 3, 0), (8, 32, 0), label,
                              fixed_note=note)
    if product == "openvoxdb":
        return grade_two_line(version, (9, 2, 0), (8, 18, 0), label)
    if product in ("puppet", "puppetserver"):
        return grade_open_source(version, label)
    if product == "trapperkeeper-authorization":
        return grade_trapperkeeper(version)
    return "UNKNOWN", "unknown product %s" % product


# ---------------------------------------------------------------------------
# Local detection
# ---------------------------------------------------------------------------

LOCAL_VERSION_FILES = (
    "/opt/puppetlabs/puppet/VERSION",
    "/opt/puppetlabs/server/data/puppetserver/VERSION",
)

LOCAL_COMMANDS = (
    ("puppet", ["puppet", "--version"]),
    ("puppetserver", ["puppetserver", "--version"]),
    ("openvox", ["openvox", "--version"]),
)

# rpm / dpkg package names mapped to the product they identify.
PACKAGE_PRODUCTS = (
    ("puppet-enterprise", "pe"),
    ("openvox-server", "openvox-server"),
    ("openvox-agent", "openvox-agent"),
    ("openvoxdb", "openvoxdb"),
    ("openvox", "openvox-server"),
    ("puppetserver", "puppetserver"),
    ("puppet-agent", "puppet-core"),
    ("puppet", "puppet"),
)


def _run(cmd, timeout=15):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (out.stdout or "") + (out.stderr or "")
    return text.strip() or None


def find_local_products():
    """Detect installed Puppet products on this box.

    Sources, in order: `puppet` / `puppetserver` / `openvox --version`,
    the VERSION files under /opt/puppetlabs, and the rpm / dpkg package
    lists. Returns a list of (product, version, source) tuples.
    """
    found = {}

    for product, cmd in LOCAL_COMMANDS:
        text = _run(cmd)
        if not text:
            continue
        version = parse_version(text)
        if version:
            # `puppet --version` on a PE box reports the Puppet Core
            # version, not the PE version; grade it as puppet-core and
            # let the package list supply the PE version.
            key = "puppet-core" if product == "puppet" else product
            found.setdefault(key, (version, " ".join(cmd)))

    for path in LOCAL_VERSION_FILES:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        version = parse_version(text)
        if version:
            found.setdefault("puppet-core", (version, path))

    pkg_text = _run(["rpm", "-qa",
                     "puppet-enterprise", "openvox-server",
                     "openvox-agent", "openvoxdb", "openvox",
                     "puppetserver", "puppet-agent", "puppet"])
    if not pkg_text:
        pkg_text = _run(["dpkg-query", "-W", "-f=${Package} ${Version}\n",
                         "puppet-enterprise", "openvox-server",
                         "openvox-agent", "openvoxdb", "openvox",
                         "puppetserver", "puppet-agent", "puppet"])
    if pkg_text:
        for line in pkg_text.splitlines():
            line = line.strip()
            if not line or "is not installed" in line:
                continue
            for pkg_name, product in PACKAGE_PRODUCTS:
                m = re.match(re.escape(pkg_name) + r"[- ](\d+\.\d+"
                             r"(?:\.\d+){0,2})", line)
                if not m:
                    m = re.match(re.escape(pkg_name) + r"\s+"
                                 r"(\d+\.\d+(?:\.\d+){0,2})", line)
                if m:
                    version = parse_version_tuple(m.group(1))
                    if version and product not in found:
                        found[product] = (version, "package %s" % line)
                    break

    return [(product, version, source)
            for product, (version, source) in sorted(found.items())]


def check_autosign():
    """Check whether the server autosigns certificate requests.

    Returns (status, detail): status is `on`, `off` or `unknown`.
    Autosign on means anyone who can reach port 8140 can get a client
    certificate, which turns the authenticated flaw into an
    unauthenticated chain.
    """
    text = _run(["puppet", "config", "print", "autosign",
                 "--section", "server"])
    if text is None:
        return "unknown", "could not run `puppet config print autosign`"
    text = text.strip()
    if text.lower() == "true":
        return "on", "autosign = true: any host that can reach port 8140 can enrol a client certificate"
    if text.lower() == "false":
        return "off", "autosign is off: certificates must be signed by hand"
    # A path to autosign.conf: read it and look for broad globs.
    path = text
    try:
        with open(path, "r", errors="replace") as fh:
            conf = fh.read()
    except OSError:
        return "unknown", "autosign points at %s, which could not be read" % path
    entries = [ln.strip() for ln in conf.splitlines()
               if ln.strip() and not ln.strip().startswith("#")]
    if not entries:
        return "off", "autosign.conf %s is empty" % path
    if "*" in entries or any(e.startswith("*") for e in entries):
        return "on", ("autosign.conf %s contains a broad glob (%s): any "
                      "matching host can enrol a certificate"
                      % (path, ", ".join(entries[:3])))
    return "unknown", ("autosign.conf %s lists %d entr%s: review them "
                       "by hand" % (path, len(entries),
                                    "y" if len(entries) == 1 else "ies"))


# ---------------------------------------------------------------------------
# Remote probe (port 8140)
# ---------------------------------------------------------------------------

def _read_der_length(data, pos):
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    nbytes = first & 0x7F
    length = int.from_bytes(data[pos:pos + nbytes], "big")
    return length, pos + nbytes


def cert_common_names(der):
    """Pull every Common Name out of a DER certificate.

    Walks the TLV stream looking for OID 2.5.4.3 (Common Name) and
    returns the string value that follows it. Only used to show which
    Puppet CA / server the cert belongs to; no verification is done.
    """
    cns = []
    oid = b"\x06\x03\x55\x04\x03"
    start = 0
    while True:
        idx = der.find(oid, start)
        if idx < 0:
            break
        pos = idx + len(oid)
        if pos >= len(der):
            break
        tag = der[pos]
        pos += 1
        if tag not in (0x13, 0x0C, 0x16, 0x14, 0x1E):
            start = pos
            continue
        try:
            length, pos = _read_der_length(der, pos)
        except IndexError:
            break
        value = der[pos:pos + length]
        try:
            cns.append(value.decode("utf-8", errors="replace"))
        except Exception:
            pass
        start = pos + length
    return cns


def probe_host(host, port=DEFAULT_PORT, timeout=15):
    """Probe a live Puppet Server. Detection only.

    One TCP connect to port 8140, one TLS handshake (no client cert,
    no verification — the cert is only read, never trusted), then one
    plain GET to /status/v1/simple, which answers 401/403 without a
    client certificate. No report is sent and nothing here can trigger
    the flaw. Returns a dict with the findings.
    """
    result = {"host": host, "port": port, "reachable": False,
              "tls": False, "cert_cns": [], "fingerprint": None,
              "status_code": None, "status_body": "",
              "verdict": "UNKNOWN", "reason": "", "warnings": []}

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        result["reason"] = (
            "could not reach %s:%d (%s). Either nothing listens there, "
            "or the port is firewalled. If this host runs Puppet "
            "Server, grade it locally with --local." % (host, port, exc)
        )
        return result
    result["reachable"] = True

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        tls_sock = ctx.wrap_socket(sock, server_hostname=host)
    except (ssl.SSLError, OSError) as exc:
        result["reason"] = (
            "%s:%d answers TCP but the TLS handshake failed (%s). "
            "Something listens on 8140 that is not a Puppet Server, or "
            "it requires a client certificate at handshake time."
            % (host, port, exc)
        )
        sock.close()
        return result

    result["tls"] = True
    try:
        der = tls_sock.getpeercert(binary_form=True)
    except Exception:
        der = None
    tls_sock.close()
    if der:
        result["cert_cns"] = cert_common_names(der)
        result["fingerprint"] = ":".join(
            "%02x" % b for b in hashlib.sha256(der).digest()[:16])

    # The status endpoint needs a client certificate; without one the
    # server answers 401/403. That is the expected, safe outcome — the
    # version is not disclosed to unauthenticated callers.
    url = "https://%s:%d%s" % (host, port, STATUS_PATH)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    insecure_ctx = ssl.create_default_context()
    insecure_ctx.check_hostname = False
    insecure_ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=insecure_ctx) as resp:
            result["status_code"] = resp.status
            result["status_body"] = resp.read().decode(
                "utf-8", errors="replace")[:500]
    except urllib.error.HTTPError as exc:
        result["status_code"] = exc.code
        try:
            result["status_body"] = exc.read().decode(
                "utf-8", errors="replace")[:500]
        except Exception:
            result["status_body"] = ""
    except (urllib.error.URLError, ssl.SSLError, OSError) as exc:
        result["warnings"].append(
            "TLS handshake worked but the status GET failed (%s). The "
            "server is still reachable on 8140." % exc)

    if result["status_code"] in (401, 403):
        result["reason"] = (
            "Puppet Server is reachable on %s:%d (TLS handshake OK, "
            "status endpoint answers HTTP %d without a client "
            "certificate, as expected). The version is NOT disclosed to "
            "unauthenticated callers, so it cannot be graded remotely: "
            "run --local on the box, or grade its version with "
            "--product/--version." % (host, port, result["status_code"])
        )
    elif result["status_code"] == 200:
        result["warnings"].append(
            "The status endpoint answered HTTP 200 without a client "
            "certificate. That is unusual for a Puppet Server — check "
            "whether auth.conf is misconfigured (see %s)."
            % CVE_COMPANION
        )
        result["reason"] = (
            "Puppet Server is reachable on %s:%d and its status "
            "endpoint answers without a client certificate. The "
            "version still was not graded: run --local on the box."
            % (host, port)
        )
    else:
        result["reason"] = (
            "Puppet Server appears reachable on %s:%d (TLS handshake "
            "OK, status endpoint answered HTTP %s). The version is not "
            "disclosed to unauthenticated callers: run --local on the "
            "box." % (host, port, result["status_code"])
        )
    if result["cert_cns"]:
        result["reason"] += " Cert CNs: %s." % ", ".join(result["cert_cns"])
    return result


# ---------------------------------------------------------------------------
# Log / report hunting
# ---------------------------------------------------------------------------

# A report event that carries an inline object type definition. Legit
# reports are plain data: `__ptype` with `Object[`, `RubyMethod` or
# `annotations` in an event is the exploitation marker the advisories
# name. The pattern needs `__ptype` plus one of the type-definition
# markers, so an ordinary string that happens to mention RubyMethod
# does not fire.
IOC_PATTERNS = (
    re.compile(r"__ptype[^}]{0,400}Object\s*\[", re.IGNORECASE),
    re.compile(r"__ptype[^}]{0,400}RubyMethod", re.IGNORECASE),
    re.compile(r"__ptype[^}]{0,400}annotations", re.IGNORECASE),
    re.compile(r"RubyMethod[^}]{0,200}body", re.IGNORECASE),
)

# Certname on a PUT /puppet/v3/report/ line in the access log.
REPORT_PUT_RE = re.compile(
    r"PUT\s+/puppet/v3/report/([A-Za-z0-9._-]+)")

MAX_HITS_SHOWN = 25


def _iter_files(paths):
    """Yield (path, opener) for every readable file under `paths`."""
    for path in paths:
        if os.path.isfile(path):
            yield path
        elif os.path.isdir(path):
            for root, _dirs, files in os.walk(path):
                for name in sorted(files):
                    yield os.path.join(root, name)


def _open_maybe_gz(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


def scan_logs(paths):
    """Grep reports / logs for the exploitation markers.

    Returns (hits, certnames, files_scanned): `hits` is a list of
    (path, line_number, line) for IOC matches, `certnames` the distinct
    certnames seen on report PUTs.
    """
    hits = []
    certnames = set()
    scanned = 0
    for path in _iter_files(paths):
        try:
            fh = _open_maybe_gz(path)
        except OSError:
            continue
        scanned += 1
        try:
            for lineno, line in enumerate(fh, 1):
                m = REPORT_PUT_RE.search(line)
                if m:
                    certnames.add(m.group(1))
                if any(p.search(line) for p in IOC_PATTERNS):
                    hits.append((path, lineno, line.strip()[:300]))
        except OSError:
            pass
        finally:
            fh.close()
    return hits, sorted(certnames), scanned


def find_prefix_impersonation(certnames):
    """Flag certnames that are another certname with an extra leading
    label — the CVE-2026-115732 impersonation shape, e.g.
    `evil.web01.example.com` next to `web01.example.com`."""
    flagged = []
    names = set(certnames)
    for name in names:
        labels = name.split(".")
        for i in range(1, len(labels)):
            suffix = ".".join(labels[i:])
            if suffix in names and suffix != name:
                flagged.append((name, suffix))
    return sorted(flagged)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

EXIT_CODES = {"PATCHED": 0, "NOT-AFFECTED": 0, "NOT-EXPOSED": 0,
              "CLEAN": 0, "VULNERABLE": 1, "SUSPICIOUS": 1,
              "UNKNOWN": 2}


def format_result(result, as_json=False):
    if as_json:
        return json.dumps(result, indent=2, sort_keys=True)
    lines = []
    if result.get("product"):
        lines.append("product: %s (%s)" % (result["product"],
                                           PRODUCT_LABELS[result["product"]]))
    if result.get("version_text"):
        lines.append("version: %s" % result["version_text"])
    if result.get("host"):
        lines.append("host: %s:%s" % (result["host"],
                                      result.get("port", DEFAULT_PORT)))
    if result.get("reachable") is not None:
        lines.append("reachable: %s" % result["reachable"])
    if result.get("tls") is not None:
        lines.append("tls: %s" % result["tls"])
    if result.get("cert_cns"):
        lines.append("cert_cn: %s" % ", ".join(result["cert_cns"]))
    if result.get("fingerprint"):
        lines.append("cert_sha256_prefix: %s" % result["fingerprint"])
    if result.get("status_code") is not None:
        lines.append("status_endpoint: HTTP %s" % result["status_code"])
    lines.append("verdict: %s" % result["verdict"])
    lines.append("reason: %s" % result["reason"])
    if result.get("source"):
        lines.append("source: %s" % result["source"])
    for warning in result.get("warnings", []):
        lines.append("WARNING: %s" % warning)
    for hit in result.get("hits", [])[:MAX_HITS_SHOWN]:
        lines.append("HIT %s:%s: %s" % hit)
    if len(result.get("hits", [])) > MAX_HITS_SHOWN:
        lines.append("... and %d more hits"
                     % (len(result["hits"]) - MAX_HITS_SHOWN))
    for name, suffix in result.get("impersonation", []):
        lines.append("IMPERSONATION?: %s looks like %s with an extra "
                     "leading label (%s — check whether %s is a real "
                     "node)" % (name, suffix, CVE_COMPANION, name))
    if result.get("certnames"):
        lines.append("report_certnames: %s"
                     % ", ".join(result["certnames"][:50]))
    return "\n".join(lines)


def fixed_table():
    rows = [
        "Puppet / OpenVox — %s + %s" % (CVE_ID, CVE_COMPANION),
        "fixed 2026-11-03; %s added to CISA KEV 2026-11-17, due 2026-12-01"
        % CVE_ID,
        "",
        "Puppet Enterprise:",
        "  2023.8.0 - 2023.8.12   -> VULNERABLE",
        "  2023.8.13 and later   -> PATCHED",
        "  2025.0.0 - 2025.12.0   -> VULNERABLE",
        "  2025.12.1 and later   -> PATCHED",
        "  2026.0.0              -> VULNERABLE",
        "  2026.0.1 and later    -> PATCHED",
        "  older than 2023.8.0   -> VULNERABLE (no fix on the line)",
        "",
        "Puppet Core (Perforce):",
        "  9.x below 9.1.3       -> VULNERABLE",
        "  9.1.3 and later       -> PATCHED",
        "  8.x below 8.22.1      -> VULNERABLE",
        "  8.22.1 and later      -> PATCHED",
        "",
        "OpenVox Server / OpenVoxDB:",
        "  9.x below 9.2.0       -> VULNERABLE (incl. 9.1.1)",
        "  9.2.0 and later       -> PATCHED",
        "  8.x below 8.18.0      -> VULNERABLE (incl. 8.17.1)",
        "  8.18.0 and later      -> PATCHED",
        "",
        "OpenVox agent:",
        "  9.x below 9.3.0       -> VULNERABLE (incl. 9.2.1)",
        "  9.3.0 and later       -> PATCHED",
        "  8.x below 8.32.0      -> VULNERABLE (incl. 8.31.2)",
        "  8.32.0 and later      -> PATCHED",
        "",
        "trapperkeeper-authorization (%s):" % CVE_COMPANION,
        "  below 2.5.0           -> VULNERABLE",
        "  2.5.0 and later       -> PATCHED",
        "",
        "Community open-source Puppet / Puppet Server:",
        "  every version         -> VULNERABLE (NO FIX — migrate to "
        "OpenVox or Puppet Core)",
        "",
        "bare versions (e.g. 2025.12, 9.2) -> UNKNOWN (give the full "
        "version)",
    ]
    return "\n".join(rows)


def grade_entry(entry):
    """Grade one inventory entry dict. Returns a result dict."""
    host = entry.get("host", "unknown")
    product = entry.get("product", "pe")
    if product not in PRODUCTS:
        return {"host": host, "product": product, "verdict": "UNKNOWN",
                "reason": "unknown product %r (known: %s)"
                % (product, ", ".join(PRODUCTS)), "warnings": []}
    version_text = entry.get("version", "")
    version = None
    if "version_file" in entry:
        try:
            with open(entry["version_file"], "r", errors="replace") as fh:
                version_text = fh.read()
        except OSError as exc:
            return {"host": host, "product": product, "verdict": "UNKNOWN",
                    "reason": "could not read %s: %s"
                    % (entry["version_file"], exc), "warnings": []}
    if version_text:
        version = parse_version(version_text)
    verdict, reason = grade_version(product, version)
    result = {"host": host, "product": product,
              "version_text": version_string(version),
              "verdict": verdict, "reason": reason, "warnings": []}
    if entry.get("autosign"):
        result["warnings"].append(
            "autosign is on for this host: anyone who can reach port "
            "8140 can enrol a client certificate, so the authenticated "
            "flaw is unauthenticated in practice. Turn off naive "
            "autosign until patched.")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detection-only triage for Puppet Enterprise / "
                    "OpenVox %s (report deserialization RCE) and %s."
                    % (CVE_ID, CVE_COMPANION))
    parser.add_argument("--local", action="store_true",
                        help="run on the Puppet box: installed packages "
                             "+ version commands + autosign")
    parser.add_argument("--product", choices=PRODUCTS,
                        help="product to grade with --version")
    parser.add_argument("--version",
                        help='version string, e.g. "2025.12.0"')
    parser.add_argument("--version-file",
                        help="file holding a version string or package "
                             "listing")
    parser.add_argument("--host",
                        help="Puppet Server hostname to probe (port 8140)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help="Puppet Server port (default 8140)")
    parser.add_argument("--logs", nargs="+",
                        help="log / report files or directories to grep "
                             "for the exploitation markers")
    parser.add_argument("--reports", nargs="+",
                        help="alias for --logs, for stored report dirs")
    parser.add_argument("--inventory-json",
                        help="fleet file: list of {host, product, version}")
    parser.add_argument("--list", action="store_true",
                        help="print the fixed-version table and exit")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    args = parser.parse_args(argv)

    if args.list:
        print(fixed_table())
        return 0

    if args.host:
        result = probe_host(args.host, port=args.port)
        print(format_result(result, args.json))
        return EXIT_CODES[result["verdict"]]

    if args.local:
        products = find_local_products()
        if not products:
            print("error: no Puppet product found on this box "
                  "(checked puppet/puppetserver/openvox --version, "
                  "/opt/puppetlabs VERSION files, rpm/dpkg). If Puppet "
                  "is installed elsewhere, use --product/--version.",
                  file=sys.stderr)
            return 3
        autosign, autosign_detail = check_autosign()
        results = []
        for product, version, source in products:
            verdict, reason = grade_version(product, version)
            result = {"product": product,
                      "version_text": version_string(version),
                      "verdict": verdict, "reason": reason,
                      "source": source, "warnings": []}
            if autosign == "on":
                result["warnings"].append(
                    "AUTOSIGN ON: %s. %s" % (autosign_detail, CVE_ID)
                    + " needs only a CA-signed client certificate, "
                    "and autosign hands those out.")
            elif autosign == "unknown":
                result["warnings"].append(
                    "autosign status unclear: %s" % autosign_detail)
            results.append(result)
        worst = max(EXIT_CODES[r["verdict"]] for r in results)
        if args.json:
            print(json.dumps(results, indent=2, sort_keys=True))
        else:
            for result in results:
                print(format_result(result, False))
                print("---")
            print("autosign: %s (%s)" % (autosign, autosign_detail))
        return worst

    log_paths = list(args.logs or []) + list(args.reports or [])
    if log_paths:
        hits, certnames, scanned = scan_logs(log_paths)
        impersonation = find_prefix_impersonation(certnames)
        if hits or impersonation:
            verdict = "SUSPICIOUS"
            reason = (
                "%d exploitation marker%s in %d file%s scanned. "
                "A report event carrying __ptype with an inline "
                "Object type / RubyMethod is the %s exploitation "
                "shape: treat the CA key as exposed until proven "
                "otherwise (preserve logs, rebuild the CA, rotate "
                "secrets the server can read)."
                % (len(hits), "" if len(hits) == 1 else "s",
                   scanned, "" if scanned == 1 else "s", CVE_ID)
            )
        elif scanned == 0:
            verdict = "UNKNOWN"
            reason = ("no readable files found under %s"
                      % ", ".join(log_paths))
        else:
            verdict = "CLEAN"
            reason = (
                "%d file%s scanned, no __ptype / RubyMethod markers "
                "found. That does not clear the host: not every report "
                "processor stores the raw event, so check EDR / auditd "
                "history too." % (scanned, "" if scanned == 1 else "s")
            )
        result = {"verdict": verdict, "reason": reason,
                  "hits": hits, "certnames": certnames,
                  "impersonation": impersonation,
                  "warnings": []}
        print(format_result(result, args.json))
        return EXIT_CODES[verdict]

    if args.inventory_json:
        try:
            with open(args.inventory_json, "r") as fh:
                entries = json.load(fh)
        except (OSError, ValueError) as exc:
            print("error: could not read %s: %s"
                  % (args.inventory_json, exc), file=sys.stderr)
            return 3
        if not isinstance(entries, list):
            print("error: inventory file must hold a JSON list",
                  file=sys.stderr)
            return 3
        results = [grade_entry(e) for e in entries]
        if args.json:
            print(json.dumps(results, indent=2, sort_keys=True))
        else:
            for result in results:
                print(format_result(result, False))
                print("---")
        return max(EXIT_CODES[r["verdict"]] for r in results)

    version_text = ""
    if args.version_file:
        try:
            with open(args.version_file, "r", errors="replace") as fh:
                version_text = fh.read()
        except OSError as exc:
            print("error: could not read %s: %s" % (args.version_file, exc),
                  file=sys.stderr)
            return 3
    elif args.version:
        version_text = args.version

    if not version_text:
        parser.print_usage(sys.stderr)
        print("error: give --local, --host, --logs, --version, "
              "--version-file, or --inventory-json", file=sys.stderr)
        return 3

    product = args.product or "pe"
    version = parse_version(version_text)
    verdict, reason = grade_version(product, version)
    result = {"product": product, "version_text": version_string(version),
              "verdict": verdict, "reason": reason, "warnings": []}
    if product in ("puppet", "puppetserver"):
        result["warnings"].append(
            "Red Hat Satellite and other products that bundle Puppet "
            "Server are affected the same way. This tool does not "
            "grade them; check the vendor advisory.")
    print(format_result(result, args.json))
    return EXIT_CODES[verdict]


if __name__ == "__main__":
    sys.exit(main())
