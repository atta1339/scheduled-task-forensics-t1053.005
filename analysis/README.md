**🛡️ Persistence Analysis — Scheduled Task Forensics (T1053.005)** 

This document provides a detailed breakdown of the two scheduled tasks discovered on the host system. Both tasks demonstrate boot‑time persistence under the SYSTEM account, aligning with MITRE ATT&CK technique T1053.005 — Scheduled Task / Task Scheduler.

🔍 T1053_005_FreshLog — Analysis
Trigger
BootTrigger

Executes automatically at every system startup.

Execution Context
User: S-1-5-18 (SYSTEM)

RunLevel: LeastPrivilege (SYSTEM still executes with full privileges)

Command
Code
powershell.exe
Arguments
Code
-WindowStyle Hidden -EncodedCommand dwBoAG8AYQBtAGkAIAAvAGEAbABsACAAPgAgAEMAOgBcAFUAcwBlAHIAcwBcAFAAdQBiAGwAaQBjAFwAcAByAG8AbwBmAC4AdAB4AHQA
Decoded Payload
Code
whoami /all > C:\Users\Public\proof.txt
Behavior Summary
Hidden PowerShell execution

Encoded Base64 payload

Writes identity information to a public directory

Confirms persistence execution

🔍 T1053_005_OnStartup — Analysis
Trigger
BootTrigger

Executes automatically at every system startup.

Execution Context
User: S-1-5-18 (SYSTEM)

RunLevel: LeastPrivilege

Command
Code
cmd.exe
Arguments
Code
/c calc.exe
Behavior Summary
Launches Calculator at startup

Visible persistence mechanism

Demonstrates SYSTEM‑level execution

🧩 MITRE ATT&CK Mapping
Technique	ID	Description
Scheduled Task	T1053.005	Persistence via Task Scheduler
PowerShell	T1059.001	Encoded payload execution
Command Execution	T1059	cmd.exe execution
Boot Autostart	T1547	Startup execution
Data Collection	T1005	whoami /all output
Indicator Hiding	T1070	Hidden PowerShell window


📝 Summary
Both scheduled tasks provide reliable SYSTEM‑level persistence.
FreshLog uses a stealthy encoded PowerShell payload, while OnStartup uses a visible cmd.exe execution.
Together, they demonstrate how attackers can maintain control over a host using Windows Task Scheduler.
