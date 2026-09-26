# Setup-TelemetryAndAuditPolicy.ps1
# Enables Task Scheduler operational logging and object access audit policy.

# 1. Enable Task Scheduler Operational Log Channel
Write-Host "Enabling Task Scheduler Operational Log..." -ForegroundColor Cyan
wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /e:true

# 2. Enable Advanced Object Access Audit Policy (Event ID 4698 generation)
Write-Host "Enabling 'Other Object Access Events' Audit Policy..." -ForegroundColor Cyan
auditpol /set /subcategory:"Other Object Access Events" /success:enable

# 3. Verify Log Channel Status
Get-WinEvent -ListLog "Microsoft-Windows-TaskScheduler/Operational" | Select-Object LogName, IsEnabled
