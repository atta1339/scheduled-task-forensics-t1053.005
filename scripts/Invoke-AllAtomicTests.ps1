# Invoke-AllAtomicTests.ps1
# Automates execution and log verification across T1053.005 Atomic Red Team tests

# 1. Execute Atomic Tests 1, 2, and 4
Write-Host "Running Atomic Red Team Tests for T1053.005..." -ForegroundColor Cyan
Invoke-AtomicTest T1053.005 -TestNumbers 1,2,4 -LoggingPath "C:\Users\Public\AtomicExecutionLog.txt"

# 2. Query Generated Telemetry
Write-Host "`n=== Operational Log (Event IDs 106 & 141) ===" -ForegroundColor Yellow
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; Id = 106, 141 } -MaxEvents 5 | 
    Select-Object TimeCreated, Id, Message

Write-Host "`n=== Security Log (Event IDs 4698 & 4699) ===" -ForegroundColor Yellow
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4698, 4699 } -MaxEvents 5 | 
    Select-Object TimeCreated, Id, Message

# 3. Cleanup Test Artifacts
Write-Host "`nCleaning up Atomic Test artifacts..." -ForegroundColor Red
Invoke-AtomicTest T1053.005 -TestNumbers 1,2,4 -Cleanup
