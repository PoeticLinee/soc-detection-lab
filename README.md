# 🛡️ Home SOC & Threat Detection Lab

**An end-to-end, hands-on Security Operations Center (SOC) lab built at home — deploying a SIEM, hardening an endpoint, ingesting telemetry, and engineering detections mapped to the MITRE ATT&CK framework.**

> Built by Przemyslaw Wierzbicki — aspiring SOC Analyst

---

## 📋 Project Overview

| | |
|---|---|
| **SIEM Platform** | Splunk Enterprise (Ubuntu Server) |
| **Endpoint Monitored** | Windows 10 |
| **Log Transport** | Splunk Universal Forwarder |
| **Endpoint Telemetry** | Sysmon 15.x |
| **Framework** | MITRE ATT&CK |
| **Virtualization** | Oracle VirtualBox (isolated host-only network) |
| **Status** | 🚧 Actively in progress — see [Roadmap](#-roadmap) |

---

## 📐 Architecture & Topology

```
┌──────────────────────────────────────────────────────┐
│           Isolated Host-Only Network (192.168.56.0/24)│
│                                                       │
│  ┌────────────────────┐         ┌───────────────────┐ │
│  │  Windows 10 Host   │         │  Ubuntu Server    │ │
│  │  192.168.56.102    │──9997─▶│  Splunk Enterprise│ │
│  │  Sysmon + UF       │         │  192.168.56.101   │ │
│  └────────────────────┘         │  :8000 (mgmt)     │ │
│                                 │  :9997 (ingest)   │ │
│                                 └───────────────────┘ │
└──────────────────────────────────────────────────────┘
```

- **Adapter 1:** Host-Only network — isolated lab communication
- **Adapter 2:** NAT — internet access for updates/tooling

---

## 📁 Repository Structure

```
soc-detection-lab/
├── README.md
├── docs/           # notes, lessons learned, findings
├── rules/          # SPL detection rules / Sigma rules
├── samples/        # sample logs, sample malicious command lines
└── scripts/        # setup / config scripts (inputs.conf, sysmonconfig.xml, etc.)
```

---

## 🚀 Implementation Progress

- ✅ **Phase 1 — SIEM Deployment**
  Deployed Splunk Enterprise on Ubuntu, management UI on port 8000, receiver enabled on port 9997.

- ✅ **Phase 2 — Endpoint Hardening & Monitoring**
  Deployed Sysmon 15.x on the Windows 10 target with a modular config; verified events in `Microsoft-Windows-Sysmon/Operational`.

- ✅ **Phase 3 — Telemetry Ingestion**
  Deployed Splunk Universal Forwarder, configured `inputs.conf` to forward Application/Security/System/Sysmon logs. Validated pipeline end-to-end in Splunk (`index=main`).

- 🔄 **Phase 4 — Threat Simulation** *(in progress — 3 techniques simulated so far)*

- 🔄 **Phase 5 — Detection Engineering** *(in progress — 3 custom alerts so far)*

- ⏳ **Phase 6 — Dashboards & Screenshots** *(planned)*

- ⏳ **Phase 7 — Incident Reports** *(planned)*

---

## ⚔️ Threat Simulation

**Technique simulated:** T1059.001 — Command and Scripting Interpreter: PowerShell

Executed an obfuscated PowerShell command that bypasses execution policy, hides the window, and downloads a file into a temp directory:

```powershell
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE' -OutFile '$env:TEMP\suspicious_script.ps1'"
```

---

**Technique simulated:** T1003.001 — OS Credential Dumping: LSASS Memory

Used Atomic Red Team to execute a credential-dumping test against the LSASS process, simulating techniques attackers use to extract cached credentials from memory:

```powershell
Invoke-AtomicTest T1003.001 -GetPrereqs
Invoke-AtomicTest T1003.001
```

---

**Technique simulated:** T1136.001 — Create Account: Local Account

Used Atomic Red Team to simulate an attacker creating a new local account for persistence:

```powershell
Invoke-AtomicTest T1136.001 -GetPrereqs
Invoke-AtomicTest T1136.001
```

---

## 🔍 Detection Engineering

**Threat hunting query — PowerShell execution (SPL):**

```spl
index=main EventCode=1 Image="*powershell.exe" (CommandLine="*-ExecutionPolicy Bypass*" OR CommandLine="*-WindowStyle Hidden*")
| table _time ComputerName User Image CommandLine ParentCommandLine
```

**Threat hunting query — LSASS credential dumping (SPL):**

```spl
index=main source="*Sysmon*" (CommandLine="*lsass*" OR CommandLine="*xordump*" OR CommandLine="*rdrleakdiag*")
| table _time host EventCode SourceImage TargetImage CommandLine
```

**Detection rule — LSASS access via Sysmon process creation / access events (SPL):**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" lsass (EventCode=1 OR EventCode=10)
| table _time, host, EventCode, SourceImage, TargetImage, CommandLine
| sort _time
```

**Threat hunting query — local account creation (SPL):**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 "net user"
| table _time, CommandLine, Image
```

**Detection rule — local account / group manipulation via Sysmon (SPL):**

```spl
index=main source="*Sysmon*" EventCode=1 (CommandLine="*net user*" OR CommandLine="*localgroup*")
| table _time host EventCode Image CommandLine User
```

| Rule | Technique | Trigger | Severity | Action |
|---|---|---|---|---|
| Suspicious Obfuscated PowerShell Execution | T1059.001 | `Number of Results > 0` | High  | Dashboard notification + event tagging |
| Suspicious LSASS Memory Access | T1003.001 | `Number of Results > 0` | Critical | Dashboard notification + event tagging |
| Suspicious Local Account / Group Manipulation | T1136.001 | `Number of Results > 0` | High | Dashboard notification + event tagging |

---

## 🔑 Key Technical Findings

- Splunk's `index=main` retains forwarded events even if an attacker later tries to clear local Windows logs — centralized logging beats local tampering.
- Matching on both `-ExecutionPolicy Bypass` and `-WindowStyle Hidden` narrows results to genuinely suspicious PowerShell invocations rather than all PowerShell activity.
- LSASS credential dumping doesn't always show up as a clean process name — tools like `xordump` or `rdrleakdiag` are used to evade signature-based detection, so hunting on process access patterns (Sysmon EventCode 10, `TargetImage=lsass.exe`) is more resilient than blocking by filename alone.
- Local account creation via `net user` is a fast, low-noise way for an attacker to establish persistence — pairing the command-line string with `localgroup` catches both the account creation and the follow-up privilege escalation (adding the new account to an admin group).
- *(More findings will be added as more techniques are tested.)*

---

## 🗺️ Roadmap

- [x] Simulate a credential access technique (T1003.001)
- [x] Simulate a persistence technique (T1136.001)
- [ ] Simulate additional MITRE ATT&CK techniques (lateral movement, defense evasion, privilege escalation)
- [ ] Write 5–10 custom detection rules covering multiple tactics
- [ ] Build a Splunk dashboard for alert overview / MITRE coverage
- [ ] Capture real screenshots of alerts and dashboards
- [ ] Write 2–3 incident reports from real alert data (timeline, root cause, containment, lessons learned)

---

## 🛠️ Technologies Used

| Category | Technology |
|---|---|
| SIEM | Splunk Enterprise |
| Endpoint Detection | Sysmon 15.x |
| Log Transport | Splunk Universal Forwarder |
| Virtualization | Oracle VirtualBox |
| Framework | MITRE ATT&CK |
| OS — SIEM | Ubuntu Server |
| OS — Endpoint | Windows 10 |

---

## 👤 About

**Przemyslaw Wierzbicki** — building hands-on SOC/detection engineering skills through this home lab.

- 🐙 GitHub: [PoeticLinee](https://github.com/PoeticLinee)
- 💼 LinkedIn: [Przemysław Wierzbicki](https://www.linkedin.com/in/przemysław-wierzbicki-42b840424/)

---

## 📄 License

MIT License