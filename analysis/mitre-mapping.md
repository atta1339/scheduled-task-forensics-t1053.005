****🧩 MITRE ATT&CK Mapping — Scheduled Task Forensics (T1053.005)****

This document maps all observed behaviors in the investigation to the MITRE ATT&CK framework.
Each technique is tied directly to evidence found in Sysmon, Security, and TaskScheduler logs.

🛡️ Persistence Techniques
T1053.005 — Scheduled Task / Task Scheduler
Why it applies:  
Both malicious tasks (T1053_005_FreshLog and T1053_005_OnStartup) were created using Windows Task Scheduler.

Evidence:

Security Event ID 4698 (Task Created)

TaskScheduler Event ID 106 (Task Registered)

XML definitions showing <BootTrigger>

⚙️ Execution Techniques
T1059 — Command and Scripting Interpreter
Why it applies:  
Both tasks execute commands via interpreters.

Evidence:

cmd.exe /c calc.exe

Sysmon Event ID 1 (Process Creation)

T1059.001 — PowerShell
Why it applies:  
FreshLog uses PowerShell with an encoded command.

Evidence:

powershell.exe -WindowStyle Hidden -EncodedCommand ...

Sysmon Event ID 1

Decoded payload: whoami /all > C:\Users\Public\proof.txt

🚀 Privilege Escalation / Boot Execution
T1547 — Boot or Logon Autostart Execution
Why it applies:  
Both tasks use <BootTrigger>, meaning they execute automatically at system startup.

Evidence:

TaskScheduler Event ID 200 (Task Triggered at Boot)

SYSTEM context (S-1-5-18)

📥 Collection Techniques
T1005 — Data from Local System
Why it applies:  
FreshLog collects system identity information using whoami /all.

Evidence:

Decoded payload

Output file: C:\Users\Public\proof.txt

Sysmon Event ID 11 (File Created)

🕶️ Defense Evasion Techniques
T1070 — Indicator Removal / Obfuscation
Why it applies:  
PowerShell payload is encoded using Base64, hiding its true intent.

Evidence:

-EncodedCommand parameter

Hidden window (-WindowStyle Hidden)

🧩 Summary Table
Technique	ID	Evidence
Scheduled Task	T1053.005	Task creation, XML, BootTrigger
Command Execution	T1059	cmd.exe execution
PowerShell	T1059.001	Encoded PowerShell payload
Boot Autostart	T1547	BootTrigger activation
Data Collection	T1005	whoami output written to file
Indicator Hiding	T1070	EncodedCommand, hidden window


📝 Final Notes
This mapping demonstrates how a simple scheduled task can chain multiple ATT&CK techniques:

Persistence

Execution

Collection

Defense Evasion

Together, they form a realistic attacker behavior pattern suitable for DFIR training, SOC analysis, and detection engineering.
