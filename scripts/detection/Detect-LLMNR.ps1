<#
.SYNOPSIS
    Detects if LLMNR (Link-Local Multicast Name Resolution) is enabled.

.DESCRIPTION
    This script checks if LLMNR is enabled on the system. LLMNR is vulnerable
    to name poisoning attacks and credential theft. It should be disabled
    in favor of DNS.

.PARAMETER ComputerName
    The computer to check. Defaults to local computer.

.EXAMPLE
    .\Detect-LLMNR.ps1
    Checks LLMNR status on local computer.

.EXAMPLE
    .\Detect-LLMNR.ps1 -ComputerName "WS01"
    Checks LLMNR status on specified computer.

.NOTES
    Author: Active Directory Hardening Project
    Reference: Project_Plan_and_Structure.md - Section 5.5.1
    
    EnableMulticast registry value:
    0 = Disabled
    1 = Enabled
    Not set = Enabled (default)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerName = $env:COMPUTERNAME
)

try {
    Write-Host "`n=== LLMNR Detection ===" -ForegroundColor Cyan
    Write-Host "Checking LLMNR status on $ComputerName...`n" -ForegroundColor White

    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    $regName = "EnableMulticast"

    if ($ComputerName -eq $env:COMPUTERNAME) {
        $llmnrSetting = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
    } else {
        $llmnrSetting = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-ItemProperty -Path $using:regPath -Name $using:regName -ErrorAction SilentlyContinue
        }
    }

    if ($null -eq $llmnrSetting) {
        Write-Host "[!] VULNERABLE: EnableMulticast not configured" -ForegroundColor Red
        Write-Host "    Current setting: Not set (LLMNR enabled by default)" -ForegroundColor Red
        Write-Host "    Risk: Vulnerable to LLMNR poisoning and credential theft`n" -ForegroundColor Red
        return $false
    }

    $value = $llmnrSetting.EnableMulticast
    Write-Host "Current EnableMulticast value: $value" -ForegroundColor Yellow

    if ($value -eq 0) {
        Write-Host "[+] SECURE: LLMNR is disabled" -ForegroundColor Green
        Write-Host "    Multicast name resolution is turned off`n" -ForegroundColor Green
        return $true
    } else {
        Write-Host "[!] VULNERABLE: LLMNR is enabled" -ForegroundColor Red
        Write-Host "    Risk: Subject to LLMNR poisoning attacks`n" -ForegroundColor Red
        return $false
    }
}
catch {
    Write-Host "[!] ERROR: Failed to check LLMNR status" -ForegroundColor Red
    Write-Host "    $_" -ForegroundColor Red
    return $null
}
