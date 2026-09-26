# Invoke-AtomicValidation.ps1
# Automates execution of Red Canary Atomic Red Team tests for T1053.005

# 1. Install Invoke-AtomicRedTeam execution framework (if not installed)
if (-not (Get-Module -ListAvailable -Name Invoke-AtomicRedTeam)) {
    Install-Module -Name Invoke-AtomicRedTeam -Scope CurrentUser -Force
}

# 2. Execute T1053.005 Atomic Tests
# Runs Test #2 (Local Scheduled Task) and Test #4 (PowerShell Cmdlet Task)
Invoke-AtomicTest T1053.005 -TestNumbers 2, 4 -LoggingPath "C:\Users\Public\AtomicResults.txt"

# 3. Clean up atomic test artifacts left on the host
Invoke-AtomicTest T1053.005 -TestNumbers 2, 4 -Cleanup
