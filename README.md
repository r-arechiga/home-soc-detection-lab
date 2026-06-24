# Home SOC Detection Lab: Sysmon + Splunk + Atomic Red Team

A self-contained detection engineering lab built from scratch to practice the full loop: simulate an attack technique, capture the telemetry, build a detection, and write it up like a real investigation.

**📄 [Full Incident Investigation Report →](incident-report.md)**

## Overview

Most home lab projects stop at "I ran the attack and saw it in the SIEM." This project goes one step further: every finding is documented as a formal incident report, written in analyst voice, as if it were a real triage. This README covers the build , the tooling, the setup, and the lessons learned along the way. The linked report covers the actual investigation.

## Stack

| Tool | Purpose | Why this one |
|---|---|---|
| **VirtualBox** | Isolated Windows 10 VM | Free, snapshot support, network isolation from host |
| **Sysmon** (SwiftOnSecurity config) | Endpoint telemetry | Default Windows logging doesn't capture process command lines, network connections, or registry changes, Sysmon does |
| **Splunk Enterprise (Free tier)** | SIEM / log correlation | No-cost, single-node, runs entirely local, no cloud account or data egress required for a personal lab |
| **Atomic Red Team** | Attack simulation | Safe, scoped technique tests mapped directly to MITRE ATT&CK, instead of running anything actually destructive |

## Architecture

Windows 10 VM (isolated, NAT network)

└── Sysmon (SwiftOnSecurity config) → Windows Event Log

└── Splunk Enterprise (local install) → indexed, searchable

└── Atomic Red Team test execution → detection validation

## Setup Notes

- VM was snapshotted immediately after a clean install (Guest Additions installed, no monitoring tools yet) to provide a reliable rollback point before running any simulated attacks.
- Sysmon was installed with the [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config) rather than defaults, since bare Sysmon logs very little without a tuned ruleset.
- Splunk's GUI-based "Add Data → Monitor → Local Event Logs" picker did not reliably list the custom `Microsoft-Windows-Sysmon/Operational` channel, despite Sysmon actively writing events to it. Rather than relying on the UI, the input was added directly via `inputs.conf`:

```ini
  [WinEventLog://Microsoft-Windows-Sysmon/Operational]
  disabled = false
  index = main
```

  This is also a more realistic, repeatable way to manage Splunk inputs than clicking through a UI every time.

## Lessons Learned (Building the Lab)

A few things worth noting that aren't analyst findings, but engineering/tooling gotchas worth remembering:

- **Splunk's GUI event log picker isn't authoritative.** A channel can be actively logging and still not appear in the "Local Event Logs" list. Editing `inputs.conf` directly is the more reliable path for custom log sources.
- **Splunk field tokenization breaks naive substring searches.** A bare keyword search for `EncodedCommand` returned zero results, even though the string existed as a substring of a logged value. Splunk indexes long strings as single tokens rather than breaking them at arbitrary points, so a wildcard-scoped query (`CommandLine="*EncodedCommand*"`) was required to actually find it. This is a real gap worth knowing before trusting a "no results" search at face value.
- **Pulling down the Atomic Red Team repo trips signature-based AV.** Windows Defender flagged technique definition files (`.md`/`.yaml`, not executable code) as `Trojan:Win32/PShellBr.YA!MTB` purely on pattern-matching, since the files document real attacker syntax. This is expected and well-documented in the ART community, but it's a good first-hand illustration of why signature-based detection alone produces noisy results, and why behavioral detection (what this lab actually builds) is a necessary complement, not a replacement.
- **VirtualBox's unattended Windows install can choke on its own answer file.** Hit a `<ProductKey>` parsing error on first boot from a stock 20H2 ISO; clicking through it dropped into normal manual setup without issue.

## What I'd Build Next

- PowerShell Script Block Logging (Event ID 4104) to capture decoded script content regardless of obfuscation
- A second technique (registry persistence or LSASS access) to broaden detection coverage
- A scheduled Splunk correlation search + alerting, rather than ad-hoc querying
- Same detection rebuilt in Microsoft Sentinel/KQL, to compare the same logic across platforms

## Related Work

This project sits alongside my other infrastructure and security work, see my [profile](https://github.com/r-arechiga) for SQL Server telemetry/alerting pipeline work and ongoing detection engineering projects as I transition toward detection engineering / cloud security.
