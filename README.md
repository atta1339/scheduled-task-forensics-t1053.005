#🛡️ Scheduled Task Persistence Forensics (MITRE ATT&CK T1053.005)
A complete Digital Forensics & Incident Response (DFIR) investigation demonstrating how Windows Scheduled Tasks can be abused for SYSTEM‑level persistence.
This case study includes:

Sysmon telemetry

EVTX log analysis

Chainsaw timeline generation

Scheduled Task XML analysis

MITRE ATT&CK mapping

Full DFIR report

Evidence artifacts

🔍 Investigation Summary
Two scheduled tasks were discovered providing boot‑time persistence:

T1053_005_FreshLog — hidden PowerShell execution with encoded payload

T1053_005_OnStartup — cmd.exe launching calc.exe

Both tasks executed automatically at startup under the SYSTEM account.

📁 Repository Structure
Code
/evidence        → Raw logs, XML tasks, timeline
/analysis        → Persistence analysis, correlation, MITRE mapping
/screenshots     → Visual evidence
/tools-used      → Chainsaw, Sysmon, EVTX export notes
/report          → Final DFIR report (PDF or Markdown)
🧩 MITRE ATT&CK Techniques
Technique	ID	Description
Scheduled Task	T1053.005	Persistence via Task Scheduler
PowerShell	T1059.001	Encoded payload execution
Command Execution	T1059	cmd.exe execution
Boot Autostart	T1547	Startup execution
Data Collection	T1005	whoami /all output
Indicator Hiding	T1070	Hidden PowerShell window


🧪 Tools Used
Sysmon

Chainsaw

Task Scheduler Operational logs

Security.evtx

PowerShell

cmd.exe

📄 Full DFIR Report
The complete investigation report is available in:

Code
/report/DFIR-Incident-Report.md
👤 Author
Atta Kouhzad 
Cybersecurity Practitioner — SOC / DFIR / Security Engineering
Melbourne, Australia
