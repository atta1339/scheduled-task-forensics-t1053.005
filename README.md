# Practical Lab Report: Auditing Scheduled Task Artifacts (MITRE ATT&CK T1053.005)

**Student Name:** Atta Kouhzad  
**Course / Unit:** Cybersecurity / Security Operations & Forensic Logging  
**Target Event Logs:** Microsoft-Windows-TaskScheduler/Operational (IDs 106, 141) & Security Log (ID 4698)  
**Environment:** Windows 11 Guest (VMware Workstation Pro) / Elevated PowerShell Admin  

---

## 1. Executive Summary
This practical exercise demonstrated the full lifecycle creation, detection, and forensic analysis of persistence mechanisms established via Windows Scheduled Tasks (MITRE ATT&CK Technique T1053.005). 

The primary goal was to map the visibility differences between default task logging and advanced security object auditing when an adversary attempts to execute obfuscated Base64 payloads.

---
## Repository Structure & Evidence

* **Raw Artifacts:** [`artifacts/Event_4698_Log.txt`](artifacts/Event_4698_Log.txt) — Captured Security Log Event ID 4698 telemetry containing raw task creation schema and Base64 argument.
* **Triage Script:** [`scripts/Decode-Payload.ps1`](scripts/Decode-Payload.ps1) — PowerShell payload decoder used during the investigation.

---

## 2. Technical Steps Executed & Artifact Capture

### Step 1: Enabling Telemetry
The operational log channel for the Windows Task Scheduler is disabled by default. Telemetry logging was explicitly enabled via `wevtutil`:
```powershell
wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /e:true
```
* **Verification:** `Get-WinEvent -ListLog "Microsoft-Windows-TaskScheduler/Operational"` confirmed `IsEnabled : True`.

### Step 2: High-Privilege Task Creation Simulation
Initial attempts to simulate task creation using standard user triggers failed due to account SID mapping constraints. To bypass this and simulate a high-privilege persistence mechanism, the task creation was explicitly assigned to the `NT AUTHORITY\SYSTEM` context:
```powershell
schtasks /Create /TN "T1053_005_Test" /TR "calc.exe" /SC DAILY /ST 23:59 /RU "NT AUTHORITY\SYSTEM" /F
```

* **Captured Artifact (Event ID 106 - Task Registration):**
  * **Event ID:** 106
  * **Task Name:** `\T1053_005_Test`
  * **User Context / SID:** `S-1-5-18` (Mapped directly to `NT AUTHORITY\SYSTEM`)

### Step 3: Simulating Deletion & Anti-Forensics Lifecycle
To simulate an adversary removing their footprint, the test task was forcibly deleted. A PowerShell query pulled the deletion log to prove a forensic trail remains:
```powershell
schtasks /Delete /TN "T1053_005_Test" /F
```
* **Captured Artifact (Event ID 141 - Task Deletion Log):**
  * **Timestamp:** 26/09/2026 5:49:31 PM
  * **Event ID:** 141
  * **Message:** `User "NT AUTHORITY\System" deleted Task Scheduler task "\T1053_005_Test"`

### Step 4: Advanced Testing with Obfuscated Payload
Adversaries rarely launch transparent processes like `calc.exe`. To simulate an evasive scenario, a command string (`whoami /all > C:\Users\Public\proof.txt`) was Base64 encoded and scheduled to launch silently on boot (`/SC ONSTART`).
```powershell
schtasks /Create /TN "T1053_005_FreshLog" /TR "powershell.exe -WindowStyle Hidden -EncodedCommand dwBoAG8AYQBtAGkAIAAvAGEAbABsACAAPgAgAEMAOgBcAFUAcwBlAHIAcwBcAFAAdQBiAGwAaQBjAFwAcAByAG8AbwBmAC4AdAB4AHQA" /SC ONSTART /RU "NT AUTHORITY\SYSTEM"
```

* **Visibility Gap Discovered:** `Event ID 106` in the `Operational` log only recorded that `\T1053_005_FreshLog` was registered. It completely omitted the command execution flags and the Base64 script parameters.

### Step 5: Unmasking Payloads via Security Log Object Auditing
To resolve the visibility gap, advanced auditing for object access was enabled:
```powershell
auditpol /set /subcategory:"Other Object Access Events" /success:enable
```
A query targeting **Event ID 4698** in the Windows **Security Log** successfully pulled the complete configuration schema of the new task:

* **Captured Advanced Artifact (Event ID 4698):**
  * **Timestamp:** 26/09/2026 6:01:29 PM
  * **Task Name:** `\T1053_005_FreshLog`
  * **Exposed Command:** `powershell.exe`
  * **Exposed Arguments:** `-WindowStyle Hidden -EncodedCommand dwBoAG8AYQBtAGkAIAAvAGEAbABsACAAPgAgAEMAOgBcAFUAcwBlAHIAcwBcAFAAdQBiAGwAaQBjAFwAcAByAG8AbwBmAC4AdAB4AHQA`

### Step 6: Programmatic Reverse-Engineering & Triage
As part of the Incident Response lifecycle, the analyst intercepted the obfuscated task configuration from the Event ID 4698 telemetry and reverse-engineered the payload string using an administrative PowerShell runtime:
```powershell
$EncodedString = "dwBoAG8AYQBtAGkAIAAvAGEAbABsACAAPgAgAEMAOgBcAFUAcwBlAHIAcwBcAFAAdQBiAGwAaQBjAFwAcAByAG8AbwBmAC4AdAB4AHQA"
$DecodedBytes = [System.Convert]::FromBase64String($EncodedString)
[System.Text.Encoding]::Unicode.GetString($DecodedBytes)
```
* **Resultant Decoded Triage:** `whoami /all > C:\Users\Public\proof.txt`
* **Impact Assessment:** The command attempts high-privilege situational awareness by dumping full group memberships, privileges, and the user SID into a globally writable public directory.

### Step 7: Environment Remediation (Eradication Phase)
Following successful extraction and string analysis, the active persistence vectors were programmatically evicted from the host to prevent latent execution:
```powershell
schtasks /Delete /TN "T1053_005_Malicious" /F
schtasks /Delete /TN "T1053_005_FreshLog" /F
```

---

## 3. Key Learnings & Takeaways
1. **Critical Logging Gaps:** Standard operational logs show *that* a task was created, but do not show *what* it executes. Without enabling advanced audit policies, hidden scripts will evade standard Event ID 106 filters.
2. **Anti-Forensics Failures:** Forcible task deletion via `schtasks /Delete` leaves a non-repudiable log entry (`Event ID 141`) tying the deletion directly to the security context responsible.
3. **The Value of Event ID 4698:** Enabling `"Other Object Access Events"` forces Windows to capture raw XML definitions, exposing hidden arguments and allowing SIEM pipelines to run decoding scripts on encoded execution strings.

---

## 4. Incident Response & Hardening Playbook
* **Containment:** If a rogue task is detected, immediately stop any active process twins via `Stop-Process` or task manager and drop network connectivity for the VM to isolate lateral movement vectors.
* **Remediation:** Forcibly delete the task using administrative overrides, then manually scrub any residual XML payload definitions located in `C:\Windows\System32\Tasks\`.
* **Hardening:** Restrict local administrator permissions using Tiered Administration models to prevent non-authorized systems from accessing elevated command channels.

---
---

## Comprehensive Event ID Forensic Reference

During scheduled task operations, events are generated across multiple Windows log channels depending on system configuration and active audit policies:

### 1. Security Log (`Security.evtx`) — *Requires Object Access Auditing*
* **`4698` — Task Created:** Captures full XML schema, executable paths, and arguments.
* **`4699` — Task Deleted:** Logged upon explicit task removal.
* **`4700` — Task Enabled:** Logged when a disabled task is activated.
* **`4701` — Task Disabled:** Logged when an active task is turned off.
* **`4702` — Task Updated:** Logged when task triggers, parameters, or actions are modified.

### 2. Task Scheduler Operational Log (`Microsoft-Windows-TaskScheduler/Operational`)
* **`106` — Task Registered:** Logged upon task configuration (omits detailed payload arguments).
* **`100` — Task Started:** Logged when the Task Scheduler engine launches the task.
* **`102` — Task Completed:** Logged when process execution finishes.
* **`129` — Process Created:** Records PID spawned by `taskeng.exe` / `svchost.exe`.
* **`140` — Task Updated:** Logged upon configuration edits.
* **`141` — Task Deleted:** Logged when `schtasks /delete` or GUI deletion occurs.

---

## Adversary Emulation via Atomic Red Team

To validate detection coverage against standardized adversary tradecraft, tests from Red Canary's **Atomic Red Team** library were executed against the host.

### Atomic Tests Covered
* **Test #1 (`T1053.005-1`):** Local Scheduled Task (`schtasks.exe`).
* **Test #2 (`T1053.005-2`):** Local Scheduled Task as SYSTEM (`NT AUTHORITY\SYSTEM`).
* **Test #4 (`T1053.005-4`):** PowerShell Cmdlet Scheduled Task (`Register-ScheduledTask`).

### Test Execution Script
* **Automated Runner:** [`scripts/Invoke-AllAtomicTests.ps1`](scripts/Invoke-AllAtomicTests.ps1) — Automates execution, log parsing, and artifact cleanup.
