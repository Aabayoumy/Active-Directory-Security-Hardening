<#
.SYNOPSIS
    Detects PowerShell logging configuration.

.DESCRIPTION
    This script checks if PowerShell script block logging and module logging
    are enabled. These logging features are critical for detecting malicious
    PowerShell activity.

.PARAMETER ComputerName
    The computer to check. Defaults to local computer.

.EXAMPLE
    .\Detect-PowerShellLogging.ps1
    Checks PowerShell logging on local computer.

.EXAMPLE
    .\Detect-PowerShellLogging.ps1 -ComputerName "Server01"
    Checks PowerShell logging on specified computer.

.NOTES
    Author: Active Directory Hardening Project
    Reference: Project_Plan_and_Structure.md - Section 5.5.6
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerName = $env:COMPUTERNAME
)

try {
    Write-Host "`n=== PowerShell Logging Detection ===" -ForegroundColor Cyan
    Write-Host "Checking PowerShell logging configuration on $ComputerName...`n" -ForegroundColor White

    $scriptBlock = {
        $results = @{}
        
        # Check Script Block Logging
        $scriptBlockPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        $scriptBlock = Get-ItemProperty -Path $scriptBlockPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
        $results.ScriptBlockLogging = if ($scriptBlock) { $scriptBlock.EnableScriptBlockLogging -eq 1 } else { $false }
        
        # Check Module Logging
        $moduleLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        $moduleLog = Get-ItemProperty -Path $moduleLogPath -Name "EnableModuleLogging" -ErrorAction SilentlyContinue
        $results.ModuleLogging = if ($moduleLog) { $moduleLog.EnableModuleLogging -eq 1 } else { $false }
        
        # Check Transcription (bonus)
        $transcriptPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
        $transcript = Get-ItemProperty -Path $transcriptPath -Name "EnableTranscripting" -ErrorAction SilentlyContinue
        $results.Transcription = if ($transcript) { $transcript.EnableTranscripting -eq 1 } else { $false }
        
        return $results
    }

    if ($ComputerName -eq $env:COMPUTERNAME) {
        $config = & $scriptBlock
    } else {
        $config = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock
    }

    $issues = @()

    Write-Host "PowerShell Logging Configuration:" -ForegroundColor Yellow
    Write-Host "==================================" -ForegroundColor Yellow
    
    # Script Block Logging
    if ($config.ScriptBlockLogging) {
        Write-Host "  [+] Script Block Logging: Enabled" -ForegroundColor Green
    } else {
        Write-Host "  [!] Script Block Logging: Disabled" -ForegroundColor Red
        $issues += "Script Block Logging not enabled"
    }

    # Module Logging
    if ($config.ModuleLogging) {
        Write-Host "  [+] Module Logging: Enabled" -ForegroundColor Green
    } else {
        Write-Host "  [!] Module Logging: Disabled" -ForegroundColor Red
        $issues += "Module Logging not enabled"
    }

    # Transcription (informational)
    if ($config.Transcription) {
        Write-Host "  [+] Transcription: Enabled (bonus)" -ForegroundColor Green
    } else {
        Write-Host "  [ ] Transcription: Disabled (optional)" -ForegroundColor Yellow
    }

    Write-Host ""
    if ($issues.Count -gt 0) {
        Write-Host "[!] VULNERABLE: PowerShell logging is not fully enabled" -ForegroundColor Red
        foreach ($issue in $issues) {
            Write-Host "    - $issue" -ForegroundColor Red
        }
        Write-Host "    Risk: Limited visibility into PowerShell-based attacks" -ForegroundColor Red
        Write-Host "    Impact: Reduced ability to detect malicious PowerShell activity`n" -ForegroundColor Red
        return $false
    } else {
        Write-Host "[+] SECURE: PowerShell logging is properly configured" -ForegroundColor Green
        return $true
    }
}
catch {
    Write-Host "[!] ERROR: Failed to check PowerShell logging configuration" -ForegroundColor Red
    Write-Host "    $_" -ForegroundColor Red
    return $null
}
