**🕒 Timeline Correlation — Scheduled Task Forensics (T1053.005)**
This document reconstructs the attacker’s activity by correlating Sysmon, Security, and TaskScheduler Operational logs.
The goal is to build a unified timeline showing task creation → registration → execution → payload behavior.

🔍 1. Scheduled Task Creation (Security.evtx)
Event ID 4698 — Scheduled Task Created
This event confirms the attacker created the tasks:

\T1053_005_FreshLog

\T1053_005_OnStartup

Key fields:

Task Name

Author (WORKGROUP\DESKTOP-TMOUBAD$)

XML contents

SYSTEM context

This is the initial persistence point.

🔍 2. Task Registration (TaskScheduler Operational)
Event ID 106 — Task Registered
Windows accepts the XML and registers the task.

Event ID 140 — Task Updated
Confirms the task is active and ready to execute.

These events validate that the persistence mechanism is successfully installed.

🔍 3. Boot Trigger Activation
Both tasks use:

Code
<BootTrigger>
So the next reboot triggers:

Event ID 200 — Task Triggered
This marks the moment the persistence activates.

🔍 4. Task Execution
Event ID 201 — Action Started
Task Scheduler begins executing the defined command.

Event ID 202 — Action Completed
Task Scheduler finishes execution.

These events show:

SYSTEM context

Command path

Execution success/failure

This is the execution point of the persistence mechanism.

🔍 5. Sysmon Process Creation (Event ID 1)
Sysmon provides the most critical evidence.

FreshLog Execution
Code
powershell.exe -WindowStyle Hidden -EncodedCommand <payload>
Decoded payload:

Code
whoami /all > C:\Users\Public\proof.txt
OnStartup Execution
Code
cmd.exe /c calc.exe
Sysmon confirms:

Parent process: taskeng.exe (Task Scheduler Engine)

User: SYSTEM

Command line: full payload

Execution timestamp

This is the payload execution point.

🔍 6. Sysmon File Creation (Event ID 11)
FreshLog produces an artifact:

Code
C:\Users\Public\proof.txt
This confirms:

PowerShell executed successfully

The encoded payload ran

Persistence produced observable output

🧩 7. Unified Attack Timeline
Below is the reconstructed chain of events:

Attacker creates scheduled tasks

Security 4698

TaskScheduler 106

Tasks registered and activated

TaskScheduler 140

System boots

Boot event

TaskScheduler 200

Tasks execute

TaskScheduler 201

TaskScheduler 202

Payload runs

Sysmon 1

PowerShell (FreshLog)

cmd.exe (OnStartup)

Artifact created (FreshLog)

Sysmon 11

This timeline confirms the attacker achieved SYSTEM‑level boot persistence using Windows Scheduled Tasks.

📝 Summary
The correlation of Sysmon, Security, and TaskScheduler logs provides a complete picture of attacker behavior:

Persistence creation

Task registration

Boot‑time activation

SYSTEM‑level execution

Payload behavior

Artifact creation

This timeline is essential for DFIR reporting, detection engineering, and SOC investigations.
