# Get-TaskSchedulerArtifacts.ps1
# Queries Windows Operational and Security Logs for T1053.005 Scheduled Task artifacts.

Write-Host "=== Querying Task Scheduler Operational Log (Event ID 106 & 141) ===" -ForegroundColor Yellow
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; Id = 106, 141 } -MaxEvents 5 | 
    Format-List TimeCreated, Id, Message

Write-Host "=== Querying Security Log for Scheduled Task Creation (Event ID 4698) ===" -ForegroundColor Yellow
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4698 } -MaxEvents 5 | 
    Format-List TimeCreated, Id, Message
