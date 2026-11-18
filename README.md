# `puppet-enterprise-scanner`

Detection-only triage for Perforce Puppet Enterprise / OpenVox `CVE-2026-115731` (report deserialization to server RCE, `CVSS 4.0 9.4`) and its companion `CVE-2026-115732` (certificate-name authorization bypass, `CVSS 4.0 9.0`). Grades your Puppet version against the fixed releases, probes a live server's port `8140` the way a defender would (one TCP connect, one TLS handshake, one plain GET that expects a `401`/`403`), and greps saved reports and logs for the exploitation markers the advisories name. No client certificate, no report body, no payloads, no exploit traffic: nothing here can trigger the flaw.

## `What it checks`

* `CVE-2026-115731` — Puppet agents send a JSON report to the server after every run, `PUT /puppet/v3/report/<certname>`. The server rebuilds each event with Puppet's rich-data deserializer, which honours a `__ptype` key: it parses the value as a Puppet type expression and builds an instance of that type. A type expression can define a new object type inline, and a `RubyMethod` annotation on one of its functions has its `body` pasted into a generated class and run through `class_eval`. Ruby executes backticks in a class body at definition time, so a crafted report runs a shell command as the `puppet` service user the moment the server parses it. `CVSS 4.0 9.4` (`CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H`), `CWE-502` deserialization of untrusted data + `CWE-94` code injection. Neodyme found it while preparing a red team engagement; the fix landed 2026-11-03.
* The report endpoint needs a client certificate signed by the Puppet CA. Every managed node already has one, and many fleets autosign new certificate requests, so in that setup an unauthenticated attacker with network access to port `8140` can enrol a certificate and then run code on the server. Code execution as `puppet` gives access to the CA signing key, so the attacker can mint certificates for any node — and, where PXP orchestration is configured, run commands as root on managed nodes.
* `CVE-2026-115732` — `trapperkeeper-authorization`, the library that enforces `auth.conf`, matched exact-hostname rules like prefix wildcards: a certificate for `evil.target.example.com` passed a rule written for `target.example.com`. Neodyme pulled PostgreSQL credentials and admin API tokens from a catalog during their engagement. Same fixed releases as above, plus `trapperkeeper-authorization 2.5.0`.
* CISA added `CVE-2026-115731` to the Known Exploited Vulnerabilities catalog on 2026-11-17, with a federal remediation deadline of 2026-12-01. CISA publishes no exploitation details, actors or victims, and no public attack report was found — the KEV entry is the exploitation evidence.

Fixed versions, per the Perforce advisory and the OpenVox advisories (all released 2026-11-03):

| `Product` | `Upgrade to` |
| --- | --- |
| `Puppet Enterprise 2023.8.x` | `2023.8.13` |
| `Puppet Enterprise 2025.x` | `2025.12.1` |
| `Puppet Enterprise 2026.0.x` | `2026.0.1` |
| `Puppet Core` | `9.1.3` / `8.22.1` |
| `OpenVox Server` | `9.2.0` / `8.18.0` |
| `OpenVox agent` | `9.3.0` / `8.32.0` |
| `OpenVoxDB` | `9.2.0` / `8.18.0` |
| `trapperkeeper-authorization` | `2.5.0` |

Community open-source Puppet and Puppet Server have **no fix at any version**. Perforce moved Puppet off its open-source licence in 2025, and Vox Pupuli says the open-source builds will not receive security updates. Migrate to OpenVox or Puppet Core.

## `Usage`

```bash
# grade a version string for a named product
python3 puppet_enterprise_scanner.py --product pe --version "2025.12.0"
python3 puppet_enterprise_scanner.py --product openvox-server --version "9.1.1"
python3 puppet_enterprise_scanner.py --product puppet --version "8.10.0"
python3 puppet_enterprise_scanner.py --product trapperkeeper-authorization --version "2.4.1"

# on the Puppet box itself (packages + version commands + autosign)
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
```

`--product` takes `pe`, `puppet-core`, `openvox-server`, `openvox-agent`, `openvoxdb`, `puppet`, `puppetserver`, or `trapperkeeper-authorization` (default `pe`). `--local` reads `puppet` / `puppetserver` / `openvox --version`, the `VERSION` files under `/opt/puppetlabs`, and the `rpm` / `dpkg` package lists, then checks whether the server autosigns certificate requests. `--host` connects to port `8140`, reads the presented TLS certificate (subject CNs + SHA-256 prefix, never trusted), then GETs `/status/v1/simple` without a client certificate: `401`/`403` is the expected answer, and the version is not disclosed to unauthenticated callers, so a remote probe can only confirm exposure — grade the version locally. `--logs` / `--reports` walk files and directories (including `.gz` logs) for `__ptype` with an inline `Object[` type, `RubyMethod`, or `annotations`, and flags certnames on report `PUT`s that look like another certname with an extra leading label (the `CVE-2026-115732` impersonation shape).

`fleet.json` is a list of `{"host": "pe-a", "product": "pe", "version": "2025.12.1"}` objects. Entries can use `"version_file"` to point at a saved version string and `"autosign": true` to record that the host autosigns.

Exit codes: `0` patched / not affected / not exposed / clean, `1` vulnerable or suspicious, `2` unknown, `3` usage error.

## `The traps`

* `The open-source trap` — community Puppet / Puppet Server has no fixed release at any version, including the latest `8.10.0`. A fully up-to-date open-source install is still vulnerable. There is no patch to install on that line. Migrate to OpenVox or Puppet Core.
* `The agent-version trap` — upgrading the agent does not fix the server. The server is the vulnerable part: `openvox-server 9.2.0 / 8.18.0` or the Puppet Enterprise fixed releases. Patch the server first.
* `The shipped-after-disclosure trap` — `openvox-agent 9.2.1` / `8.31.2` and `openvox-server 9.1.1` / `8.17.1` shipped 23–29 October, after the bug was reported but before the fix landed. They are still vulnerable. `9.2.1` is not `9.3.0`.
* `The bare-version trap` — `2025.12` with no patch level says nothing: `2025.12.0` is vulnerable and `2025.12.1` is the fix. It grades `UNKNOWN`. Get the full version from `puppet --version`, the package list, or the advisory table.
* `The autosign trap` — the flaw needs a CA-signed client certificate, which sounds like a high bar until you check autosign. `autosign = true` or a broad glob in `autosign.conf` means anyone who can reach port `8140` can enrol a certificate. The tool checks this with `--local` and warns. Turn off naive autosign until patched.
* `The 115732 companion trap` — the same releases fix the certname bypass, but it is a separate flaw with separate fallout: an attacker who gets any certificate can impersonate another node and pull its catalog (which often holds secrets). After upgrading, test custom `auth.conf` rules — exact-match rules are stricter now.
* `The CA-key trap` — exploitation gives the attacker the CA signing key. Patching does not un-leak it. If the server was exposed while vulnerable, rebuild the CA, reissue every agent certificate, revoke the old ones, and rotate every secret the server can read or hand out (Hiera eyaml keys, catalog-embedded passwords and API tokens, PuppetDB credentials, r10k / Code Manager deploy keys, cloud credentials on the server host).
* `The clean-log trap` — `--logs` finding nothing does not clear the host. Not every report processor stores the raw event, so a missing marker is not proof of no exploitation. Check EDR or `auditd` history too.
* `The remote-probe trap` — Puppet Server does not disclose its version to unauthenticated callers, so `--host` can only confirm the server is reachable on `8140`. A reachable server grades `UNKNOWN`, never clean. Grade the version on the box with `--local`.
* `The Satellite trap` — Red Hat Satellite and other products that bundle Puppet Server are affected the same way. This tool does not grade them; check the vendor advisory.

## `Why version + port probe + log grep`

Puppet Server does not hand its version to unauthenticated callers, so there is no remote version check to do — the version has to be graded from the box itself, and the remote probe only establishes exposure. The vendor and the advisories name the exact exploitation markers (`__ptype` with an inline object type, `RubyMethod` annotations), so the log grep hunts for those instead of replaying anything. Nothing here sends a report, a certificate request, or any payload — the request that triggers the flaw is never constructed.

## `Sources and disagreements`

* Perforce Puppet Enterprise security advisory (2026-11-03): the `2023.8.13` / `2025.12.1` / `2026.0.1` fixes and the `9.1.3` / `8.22.1` Puppet Core fixes. Primary source for everything graded here.
* OpenVox advisories `GHSA-ffr6-rwpm-p5wq` (report deserialization RCE) and `GHSA-q4hm-33rc-572g` (certname authorization bypass), published 2026-11-03 20:04 UTC: the mechanism, the working report shape, the `9.2.0` / `8.18.0` server and `9.3.0` / `8.32.0` agent fixes, the `2.5.0` trapperkeeper fix. The fix commit swaps the event reader from `FromDataConverter` to `ToStringifiedConverter`.
* Neodyme write-up (2026-11-03): found both bugs during a red team engagement, confirmed the RCE back to Puppet `6.24.0` (July 2021), and showed the CA-key to PXP orchestration escalation.
* Vox Pupuli (2026-11-03): all known Puppet implementations are vulnerable; open-source Puppet has no fix and will not receive security updates; migrate to OpenVox.
* CISA KEV: `CVE-2026-115731` added 2026-11-17, due 2026-12-01, listed as Perforce Puppet Enterprise. `CVE-2026-115732` is not in KEV as of 2026-11-17.
* NVD: both CVE records published 2026-11-03, CNA Perforce. The `9.4` score is the CNA's `CVSS 4.0` rating; one aggregator (CVETodo) lists `9.9` for `CVE-2026-115731`. The tool follows the CNA's `9.4` and notes the disagreement — either way it is critical and actively exploited.
* Corgea research (2026-11-17/18): the version table above, the tag check proving `openvox-agent 9.2.1` / `8.31.2` and `openvox-server 9.1.1` / `8.17.1` still call `FromDataConverter`, the autosign and IOC guidance, and the remediation checklist (rebuild the CA, rotate secrets).
* No public nuclei template is indexed for `CVE-2026-115731` (checked 2026-11-18), and no Metasploit or Exploit-DB entry was found. The OpenVox advisory publishes a working report as its proof of concept — this tool does not republish it. No dedicated public version scanner for this CVE was found.

## `Thanks to`

* Neodyme — found both bugs, reported them, and published the write-up the day the fixes shipped.
* The OpenVox project and Vox Pupuli — the advisories, the fix, and the straight answer that open-source Puppet has no patch.
* Perforce — the Puppet Enterprise advisory and the fixed releases.

## `Disclaimer`

Detection only, for defenders checking their own infrastructure. Educational use. If you are not supposed to be on the server, do not run this against it.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
