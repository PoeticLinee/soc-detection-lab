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
│  │  Windows 10 Host   │  [PORT:]│  Ubuntu Server    │ │
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

- 🔄 **Phase 4 — Threat Simulation** *(in progress — 1 technique simulated so far)*

- 🔄 **Phase 5 — Detection Engineering** *(in progress — 1 custom alert so far)*

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

## 🔍 Detection Engineering

**Threat hunting query (SPL)** — isolates PowerShell process creation events using suspicious execution flags:

```spl
index=main EventCode=1 Image="*powershell.exe" (CommandLine="*-ExecutionPolicy Bypass*" OR CommandLine="*-WindowStyle Hidden*")
| table _time ComputerName User Image CommandLine ParentCommandLine
```

| Rule | Technique | Trigger | Severity | Action |
|---|---|---|---|---|
| Suspicious Obfuscated PowerShell Execution | T1059.001 | `Number of Results > 0` | High / Critical | Dashboard notification + event tagging |

---

## 🔑 Key Technical Findings

- Splunk's `index=main` retains forwarded events even if an attacker later tries to clear local Windows logs — centralized logging beats local tampering.
- Matching on both `-ExecutionPolicy Bypass` and `-WindowStyle Hidden` narrows results to genuinely suspicious PowerShell invocations rather than all PowerShell activity.
- *(More findings will be added as more techniques are tested.)*

---

## 🗺️ Roadmap

- [ ] Simulate additional MITRE ATT&CK techniques (persistence, credential access, lateral movement)
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
- 💼 LinkedIn: (https://www.linkedin.com/in/przemysław-wierzbicki-42b840424/)

---

## 📄 License

MIT License