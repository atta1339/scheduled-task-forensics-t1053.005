* ### 🛡️ DFIR Incident Report — Scheduled Task Persistence (MITRE ATT&CK T1053.005)

Analyst: Atta Kouhzad
Date: 27 September 2026
Host: WORKGROUP\DESKTOP‑TMOUBAD
Case Type: Persistence Investigation
Classification: Internal DFIR Lab Case Study

***📌 1. Executive Summary***
This DFIR investigation identified two scheduled tasks providing SYSTEM‑level boot persistence on a Windows workstation. Both tasks executed automatically at startup, one using a hidden encoded PowerShell payload and the other launching a visible application via cmd.exe.

Sysmon, Security, and TaskScheduler logs were correlated to reconstruct the full attacker timeline. The findings align with MITRE ATT&CK technique T1053.005 — Scheduled Task / Task Scheduler, commonly used by adversaries to maintain persistence.

No lateral movement, privilege escalation attempts, or additional malicious artifacts were identified beyond the scheduled tasks.

***🎯 2. Scope of Investigation***
This investigation covers:

Extraction and analysis of scheduled task XML files

Decoding PowerShell payloads

Correlation of Sysmon, Security, and TaskScheduler logs

Reconstruction of attacker timeline

MITRE ATT&CK technique mapping

Identification of artifacts and IOCs

Recommendations for remediation and hardening

### 🧩 3. Persistence Mechanisms Identified

***3.1 Scheduled Task: T1053_005_FreshLog***
Trigger: BootTrigger
Execution: Runs at every system startup
User Context: SYSTEM (S-1-5-18)
RunLevel: LeastPrivilege (SYSTEM still executes with full privileges)

Command:

Code
powershell.exe
Arguments:

Code
-WindowStyle Hidden -EncodedCommand dwBoAG8AYQBtAGkAIAAvAGEAbABsACAAPgAgAEMAOgBcAFUAcwBlAHIAcwBcAFAAdQBiAGwAaQBjAFwAcAByAG8AbwBmAC4AdAB4AHQA
Decoded Payload:

Code
whoami /all > C:\Users\Public\proof.txt
Behavior Summary:

Hidden PowerShell execution

Encoded Base64 payload

Collects identity information

Writes output to a public directory

Confirms persistence execution

**3.2 Scheduled Task: T1053_005_OnStartup**
Trigger: BootTrigger
Execution: Runs at every system startup
User Context: SYSTEM
RunLevel: LeastPrivilege

Command:

Code
cmd.exe
Arguments:

Code
/c calc.exe
Behavior Summary:

Launches Calculator at startup

Visible persistence mechanism

Demonstrates SYSTEM‑level execution

### 🕒 4. Timeline Correlation

This timeline is reconstructed using Sysmon, Security.evtx, and TaskScheduler Operational logs.

4.1 Task Creation
Security Event ID 4698

Scheduled task created

Author: WORKGROUP\DESKTOP‑TMOUBAD$

SYSTEM context confirmed

4.2 Task Registration
TaskScheduler Event ID 106 / 140

Task registered successfully

XML accepted by Task Scheduler

4.3 Boot Trigger Activation
TaskScheduler Event ID 200

Task triggered at system startup

4.4 Task Execution
TaskScheduler Event ID 201 / 202

Action started

Action completed

4.5 Payload Execution
Sysmon Event ID 1 — Process Creation

FreshLog:

Code
powershell.exe -WindowStyle Hidden -EncodedCommand <payload>
OnStartup:

Code
cmd.exe /c calc.exe
4.6 Artifact Creation
Sysmon Event ID 11 — File Created

Code
C:\Users\Public\proof.txt

### 🧩 5. MITRE ATT&CK Mapping

Technique	ID	Description
Scheduled Task	T1053.005	Persistence via Task Scheduler
Command Execution	T1059	cmd.exe execution
PowerShell	T1059.001	Encoded PowerShell payload
Boot Autostart	T1547	Startup execution
Data Collection	T1005	whoami /all output
Indicator Hiding	T1070	Hidden PowerShell window


### 🧪 6. Indicators of Compromise (IOCs)

Scheduled Tasks
\T1053_005_FreshLog

\T1053_005_OnStartup

Commands
powershell.exe -WindowStyle Hidden -EncodedCommand ...

cmd.exe /c calc.exe

Artifacts
C:\Users\Public\proof.txt

User Context
SYSTEM (S-1-5-18)

### 📊 7. Impact Assessment

SYSTEM‑level persistence grants full control over the host

Boot‑time execution ensures reliable persistence

Encoded PowerShell payload indicates stealth intent

Public directory artifact may expose system information

Visible payload (calc.exe) confirms task execution

No evidence of:

lateral movement

privilege escalation

credential theft

network propagation

### 🔧 8. Remediation Recommendations

Immediate Actions
Delete both scheduled tasks

Remove C:\Users\Public\proof.txt

Review all SYSTEM‑level scheduled tasks

Audit TaskScheduler Operational logs for anomalies

Hardening
Enable Script Block Logging

Restrict SYSTEM‑level scheduled task creation

Enforce Sysmon configuration with command line monitoring

Disable PowerShell for non‑admin users

Implement LAPS / strong credential hygiene

### 📝 9. Conclusion

The investigation confirms two scheduled tasks providing SYSTEM‑level persistence on the host. Both tasks executed successfully at boot, with one producing a visible payload and the other silently collecting system identity information.

Sysmon, Security, and TaskScheduler logs corroborate the full attack chain.
This activity aligns with MITRE ATT&CK T1053.005 and demonstrates how adversaries can maintain stealthy, reliable persistence using Windows Scheduled Tasks.

This case serves as a complete DFIR example suitable for SOC training, DFIR portfolio use, and detection engineering.
