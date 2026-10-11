# Incident Report — IR-001

## Multi-Stage Attack Chain: Execution → Credential Access → Persistence → Collection → Exfiltration

| | |
|---|---|
| **Incident ID** | IR-001 |
| **Classification** | Simulated Intrusion (Controlled Red-Team Exercise, Home SOC Lab) |
| **Severity** | Critical |
| **Status** | Resolved (Detected & Documented) |
| **Affected Host** | `Windows10-Victim` (192.168.56.102) |
| **Affected User** | Local user, simulated victim account |
| **Analyst** | Przemyslaw Wierzbicki |
| **Date of Incident** | 2026-10-09 |
| **Detection Source** | Splunk Enterprise — Sysmon telemetry (`index=main`) |

> **Note:** This incident was generated in a fully isolated, host-only VirtualBox lab using Atomic Red Team to simulate adversary behavior mapped to MITRE ATT&CK.

---

## 1. Executive Summary

On 2026-10-09, Splunk's multi-stage correlation search flagged `Windows10-Victim` for exhibiting **5 distinct stages of a MITRE ATT&CK-mapped attack chain** within a single short window: obfuscated PowerShell execution, LSASS credential dumping, local account persistence, data archiving, and exfiltration to an external web service. Each stage was independently detected by a dedicated SPL alert; the correlation search subsequently escalated the combined activity to **Critical** severity, consistent with an active, in-progress compromise rather than isolated suspicious events.

The attacker chain demonstrates a textbook intrusion pattern: gain code execution, harvest credentials, establish a persistence foothold, stage data for theft, and exfiltrate it — all within roughly 45 minutes.

---

## 2. Timeline of Events

| Time (UTC+2) | Stage | MITRE Technique | Action Observed |
|---|---|---|---|
| 11:40:12 | 1. Execution | T1059.001 | Obfuscated PowerShell launched with `-ExecutionPolicy Bypass -WindowStyle Hidden`, downloading a remote file to `%TEMP%` |
| 11:48:49 | 2. Credential Access | T1003.001 | PowerShell spawned processes accessing `lsass.exe` memory using `xordump`/`rdrleakdiag`-style evasion tooling |
| 12:02:59 | 3. Persistence | T1136.001 | New local account `T1136.001_Admin` created via `net user /add`, then added to the local `administrators` group via `net localgroup` |
| 12:03:14 | 3. Persistence (cont.) | T1136.001 | Second account `T1136.001_CMD` created from `cmd.exe`, confirming the technique across both PowerShell and native shell execution paths |
| 11:50:00 – 11:50:17 | 4. Collection | T1560.001 | Local files staged and compressed using `7z.exe`, `WinRAR`, `WinZip`, and `makecab.exe` into multiple archive formats |
| 12:08:33 | 5. Exfiltration (prep) | T1567 | PowerShell process initiated outbound HTTPS connection to `185.199.110.133:443` |
| 12:10:48 | 5. Exfiltration | T1567 | `curl.exe` uploaded the local `C:\Windows\System32\drivers\etc\hosts` file as form data to the public API endpoint `https://reqres.in/api/users`, receiving a `200 OK` with a persisted record ID — confirming successful data transfer |

**Total observed duration:** ~45 minutes from initial execution to confirmed exfiltration.

---

## 3. Evidence

All evidence below was captured directly from live Splunk searches against Sysmon telemetry (`index=main`).

| Stage | Evidence | Screenshot |
|---|---|---|
| Execution (T1059.001) | PowerShell process creation event matching obfuscation flags | `docs/assets/splunk-detection.png` |
| Credential Access (T1003.001) | 8 events showing LSASS access via evasion tooling | `docs/assets/lsass-detecion.png` |
| Persistence (T1136.001) | 5 events: account creation + admin group addition | `docs/assets/net-user-add.png` |
| Collection (T1560.001) | 13 events across 4 different archive utilities | `docs/assets/data-archiving-detection.png` |
| Exfiltration (T1567) | `curl.exe` upload + outbound connection (EventCode 1 & 3) | `docs/assets/exfiltration-data.png` |
| Correlation (all stages) | Single correlation search tagging and grouping all 5 stages on one host | `docs/assets/multi_stage_attack_part1.png`, `docs/assets/multi_stage_attack_part2.png` |

**Key artifact — correlation search output:**

```
host: Windows10-Victim
stages_count: 5
stages_detected: 1. Execution(T1059.001), 2. Credential Access(T1003.001),
                  3. Persistence(T1136.001), 4. Collection(T1560.001),
                  5. Exfiltration(T1567)
```

This single result confirms all five kill-chain stages were executed by — and attributed to — the same host within the incident window, which is what triggered the Critical-severity correlation alert.

---

## 4. Investigation

Analysis of the `CommandLine`, `Image`, `SourceImage`/`TargetImage`, and `DestinationIp`/`DestinationPort` fields across the five SPL detections confirmed a coherent, single-actor attack chain rather than five unrelated alerts:

- The initial PowerShell process (Execution) matched the same host and time window as the subsequent LSASS access attempts (Credential Access), suggesting the dumping tooling was downloaded or invoked directly from the initial PowerShell session.
- The account-creation commands (Persistence) used native `net.exe`/`cmd.exe`, indicating the attacker pivoted away from PowerShell — likely to blend in with normal administrative activity and reduce PowerShell-specific detection surface.
- The archiving commands (Collection) targeted multiple different utilities (7-Zip, WinRAR, WinZip, makecab) for the same underlying goal, which is consistent with "living off the land" behavior — using whatever compression tool is already present rather than dropping new malware.
- The final exfiltration used `curl.exe` to upload directly to a legitimate public API (`reqres.in`) rather than to attacker-owned infrastructure — a technique that evades domain/IP reputation-based detections, since the destination has no prior malicious history.

No lateral movement to other hosts was observed in this incident; all activity was confined to `Windows10-Victim`.

---

## 5. Root Cause

The simulated entry vector was local execution of an obfuscated PowerShell command (consistent with a phishing payload, malicious script, or an attacker already holding initial local access). No exploitation of a specific software vulnerability was involved — the "root cause" in this exercise is the **absence of application allow-listing / constrained language mode**, which allowed an obfuscated PowerShell command with bypassed execution policy to run unobstructed and chain into credential theft, persistence, and exfiltration without further restriction.

---

## 6. Containment & Remediation

Actions that would be taken in a live environment, validated against this lab's telemetry:

1. **Isolate the host** — remove `Windows10-Victim` from the network pending forensic imaging.
2. **Revoke the rogue accounts** — disable/delete `T1136.001_Admin` and `T1136.001_CMD`, and audit the local `administrators` group for any other unauthorized members.
3. **Rotate credentials** — treat all credentials cached on the host as compromised following the LSASS access; force password resets for any accounts that logged into the host during the incident window.
4. **Block the exfiltration destination** — add `reqres.in` and the observed destination IP (`185.199.110.133`) to the network block list pending further triage, and review proxy/firewall logs for any other hosts communicating with the same endpoint.
5. **Hunt for related activity** — re-run the correlation search lab-wide (`stages_count >= 2`) to catch any host that triggered partial stages of this chain but didn't cross the 3-stage correlation threshold.

---

## 7. Lessons Learned

- **Correlation beats isolation.** None of the five individual alerts alone would have justified a Critical-severity, "stop everything" response — but seeing all five fire against the same host inside one window is unambiguous evidence of an active intrusion. This is the core argument for building correlation searches rather than relying purely on single-signature alerts.
- **LSASS access detection needs to be behavior-based.** Relying on a filename blocklist (e.g., blocking `mimikatz.exe`) would have missed this entirely, since the simulated tooling used generic/renamed binaries. Hunting on `TargetImage=lsass.exe` + `EventCode=10` is far more durable.
- **"Living off the land" defeats single-tool detections.** The Collection stage alone used four different legitimate compression utilities for the same goal — any rule matching only one tool name would have missed 75% of the activity.
- **Legitimate-looking exfiltration destinations are a blind spot.** A reputation-based or domain-blocklist-only approach would not have caught the exfiltration to `reqres.in`, since it is not a flagged malicious domain. Process-level context (an unusual binary like `curl.exe` making an outbound POST carrying a sensitive local file) was the deciding signal.

---

## 8. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 |
| Persistence | Create Account: Local Account | T1136.001 |
| Collection | Archive Collected Data: Archive via Utility | T1560.001 |
| Exfiltration | Exfiltration Over Web Service | T1567 |

See the full visual coverage in the [MITRE ATT&CK Navigator Heatmap](../README.md#️-mitre-attck-navigator-heatmap) in the main README.

---

## 9. Detection Rules Referenced

See [`README.md`](../README.md#-detection-engineering) for the full SPL for each rule below:

- Suspicious Obfuscated PowerShell Execution (T1059.001)
- Suspicious LSASS Memory Access (T1003.001)
- Suspicious Local Account / Group Manipulation (T1136.001)
- Suspicious Archive Utility Usage — Data Staging (T1560.001)
- Suspicious Outbound File Upload — Exfiltration (T1567)
- **Multi-Stage Attack Chain Detected** (correlation search, all techniques above)