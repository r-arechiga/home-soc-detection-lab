# Incident Investigation Report

**Host:** DESKTOP-KJ90UE9
**Date:** 06/20/2026
**Analyst:** Ryan Arechiga

---

## 1. Executive Summary

An alert from our enterprise security tooling was received at approximately 12:11 PM PST, flagging potentially malicious activity on a company workstation. The triggering event was a PowerShell process invoked with a parameter commonly used to obscure command content from plain-text detection. Following analysis, the activity was confirmed to originate from an authorized offensive security testing module rather than a malicious actor. No isolation or eradication action was required. Recommendations for more robust alerting and monitoring are detailed in Section 7.3.

## 2. Environment & Visibility

Logging was provided by native Windows Event Viewer and Sysmon, configured with the SwiftOnSecurity baseline ruleset for expanded process, network, and registry visibility. All telemetry was ingested into our SIEM, Splunk Enterprise, for correlation and search.

## 3. Detection / Trigger

At 12:11 PM PST on 06/20/2026, host DESKTOP-KJ90UE9 generated a Sysmon Event ID 1 (Process Create) event for `powershell.exe`. The triggering indicator was the presence of an encoded-command-style switch within the process command line.

## 4. Timeline of Events

| Time (PST) | Event |
|---|---|
| 12:11:16 PM | Sysmon Event ID 1 logged on DESKTOP-KJ90UE9: `powershell.exe` (PID 3160) launched with a command line containing an `-EncodedCommand`-style switch. Parent process: `powershell_ise.exe`. User: `User1`. |
| ~12:11 PM | Independent of SIEM correlation, Windows Defender flagged related files associated with the testing module via static signature detection (`Trojan:Win32/PShellBr.YA!MTB`) and removed them from the host. This represents a second, independent detection layer responding to the same activity through a different mechanism, signature-based pattern matching rather than behavioral log analysis, and illustrates the value of layered, defense-in-depth detection. |

<img width="1000" height="900" alt="image" src="https://github.com/user-attachments/assets/64843ff9-840c-44d8-91ab-caa5631c8925" />


## 5. Investigation & Analysis

### 5.1 Initial Findings

The triggering process was executed under the context of the machine's assigned local user, `User1`. `powershell.exe` was the process image responsible for executing the flagged command. The full logged command line was:

"powershell.exe" & {Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType Hyphen -EncodedCommandParamVariation E -Execute -ErrorAction Stop}

<img width="1200" height="600" alt="image" src="https://github.com/user-attachments/assets/c0efc985-55b6-44e1-9fae-765e4e34f02b" />


### 5.2 Payload Analysis

Analysis of the command line identified `Out-ATHPowerShellCommandLineParameter` as a function belonging to the **AtomicTestHarnesses** PowerShell module, which generates, and optionally executes, `powershell.exe` command-line variations for detection testing purposes. Breaking down the parameters:

- `-CommandLineSwitchType Hyphen` specifies standard hyphen-style switch formatting.
- `-EncodedCommandParamVariation E` specifies the abbreviated, valid form of `-EncodedCommand` (`-E`).
- `-Execute` causes the generated `powershell.exe` invocation to actually run, rather than merely being printed for review.

No further child process activity or outbound network connections (Sysmon Event ID 3) were observed under this process's `ProcessGuid`, indicating the executed test harness did not spawn a real encoded payload beyond the test invocation itself.

### 5.3 Technique Context

The `-EncodedCommand` parameter is a well-documented method used by threat actors to obscure malicious PowerShell content from plain-text log review and naive string-matching defenses, by passing a Base64-encoded (UTF-16LE) command. This behavior maps to **MITRE ATT&CK T1059.001 (Command and Scripting Interpreter: PowerShell)**. In this case, the parameter usage originated from the AtomicTestHarnesses module, which is purpose-built for authorized detection-engineering validation of this exact technique, rather than genuine attacker tradecraft.

## 6. Detection Logic

The following Splunk query was used to detect this activity:

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell.exe"
| regex CommandLine="(?i)-en\w*\s"
| table _time, ComputerName, User, ParentImage, Image, CommandLine
```

<img width="1568" height="353" alt="image" src="https://github.com/user-attachments/assets/cd7d23d9-3165-462f-814f-73a7638863cd" />


This query is scoped to Sysmon **Event ID 1 (Process Create)**, restricted to processes where the image is `powershell.exe`, and filters on a case-insensitive regex matching any abbreviation of `-EncodedCommand` (`-en`, `-enc`, `-encodedcommand`, etc.) followed by a space. The regex approach was chosen deliberately over an exact-string match, since PowerShell accepts unambiguous parameter abbreviations, an attacker using `-enc` instead of the full parameter name would evade a literal `-EncodedCommand` match entirely.

**Methodology note:** Initial triage attempted an exact-match keyword search for the term `EncodedCommand`, which returned zero results. This was due to Splunk's field tokenization treating `EncodedCommandParamVariation` as a single indivisible token rather than a substring match against `EncodedCommand`. A wildcard-scoped search against the `CommandLine` field was required to surface the indicator, a methodology note worth retaining for future investigations relying on exact-match keyword searches against unstructured log text.

**False-positive considerations:** Legitimate IT tooling (RMM platforms, deployment/configuration management software) sometimes uses `-EncodedCommand` to safely pass complex commands through multiple shell layers without escaping issues. A production deployment of this detection would benefit from a baseline allowlist of known-legitimate parent processes to reduce alert fatigue.

## 7. Containment, Eradication & Remediation

### 7.1 Containment Decision

A process matching the detection criteria did execute on the host; however, decoded payload analysis (Section 5.2) confirmed the executed content originated from an authorized testing module and was non-malicious. No outbound network connections or follow-on process activity were observed under the originating `ProcessGuid`. Based on this, host isolation was not pursued. In a production environment, the same initial indicator, prior to payload confirmation, would warrant precautionary network isolation pending analysis, given this technique's strong association with post-exploitation tooling.

### 7.2 Eradication

No malicious code, persistence mechanism, or dropped artifacts were identified as a result of this activity. The triggering process originated from an authorized red-team testing module rather than a malicious actor; no eradication action was required.

### 7.3 Remediation / Hardening Recommendations

- Operationalize the detection query in Section 6 as a scheduled correlation search with alerting, rather than relying on ad-hoc search.
- Enable **PowerShell Script Block Logging** (Event ID 4104) to capture decoded script content directly, independent of how the original command line was obfuscated.
- Build a baseline allowlist of legitimate parent processes/services that use `-EncodedCommand` in normal operation, to reduce false-positive volume before broader deployment.
- Develop a dashboard surfacing `-EncodedCommand` (and abbreviated variants) usage across the environment for ongoing visual monitoring.

## 8. Verification

Following the initial detection, the Splunk environment was queried over an extended time window for recurrence of the indicator and for any related activity under the same `ParentProcessGuid`. No additional encoded-command executions or follow-on indicators were observed on this host following the initial event.


