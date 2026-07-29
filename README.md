\# 🛡️ Home SOC \& Threat Detection Lab



!\[Splunk](https://img.shields.io/badge/SIEM-Splunk\_Enterprise-orange)

!\[Windows](https://img.shields.io/badge/OS-Windows\_10-blue)

!\[Ubuntu](https://img.shields.io/badge/OS-Ubuntu\_Linux-red)

!\[MITRE](https://img.shields.io/badge/Framework-MITRE\_ATT%26CK-green)



An end-to-end implementation of a virtualized Security Operations Center (SOC) environment focused on endpoint monitoring, telemetry ingestion, threat hunting, and custom detection engineering.



\---



\## 📌 Table of Contents

\- \[Architecture \& Topology](#-architecture--topology)

\- \[Configuration \& Telemetry](#-configuration--telemetry)

\- \[Threat Simulation](#-threat-simulation)

\- \[Detection Engineering \& Hunting](#-detection-engineering--hunting)



\---



\## 📐 Architecture \& Topology



```mermaid

graph TD

&#x20;   A\[Windows 10 Victim Host] -->|Sysmon \& WinEventLog| B\[Splunk Universal Forwarder]

&#x20;   B -->|Encrypted Telemetry / Port 9997| C\[Ubuntu Server / Splunk Enterprise]

&#x20;   C -->|SPL Analysis \& Alerts| D\[SOC Analyst]

