<#
.SYNOPSIS
    Detects if NTLMv1/LM authentication is enabled.

.DESCRIPTION
    This script checks the LM Authentication Level to determine if legacy
    NTLMv1 or LM authentication protocols are enabled. These protocols are
    vulnerable to relay attacks and hash cracking.

.PARAMETER ComputerName
    The computer to check. Defaults to local computer.

.EXAMPLE
    .\Detect-NTLMv1Authentication.ps1
    Checks the local computer for NTLMv1 configuration.

.EXAMPLE
    .\Detect-NTLMv1Authentication.ps1 -ComputerName "DC01"
    Checks the specified computer for NTLMv1 configuration.

.NOTES
    Author: Active Directory Hardening Project
    Reference: Project_Plan_and_Structure.md - Section 5.2.1 H-02
    ISO 27001: Control 8.5
    MITRE ATT&CK: T1557.001 (LLMNR/NBT-NS Poisoning)
    
    LmCompatibilityLevel values:
    0 = Send LM & NTLM responses
    1 = Send LM & NTLM (use NTLMv2 session security if negotiated)
    2 = Send NTLM response only
    3 = Send NTLMv2 response only
    4 = Send NTLMv2 response only (refuse LM)
    5 = Send NTLMv2 response only (refuse LM & NTLM)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerName = $env:COMPUTERNAME
)

try {
    Write-Host "`n=== NTLMv1/LM Authentication Detection ===" -ForegroundColor Cyan
    Write-Host "Checking LM Authentication Level on $ComputerName...`n" -ForegroundColor White

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $regName = "LmCompatibilityLevel"

    if ($ComputerName -eq $env:COMPUTERNAME) {
        $lmLevel = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
    } else {
        $lmLevel = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-ItemProperty -Path $using:regPath -Name $using:regName -ErrorAction SilentlyContinue
        }
    }

    if ($null -eq $lmLevel) {
        Write-Host "[!] VULNERABLE: LmCompatibilityLevel not set (defaults to 0-3)" -ForegroundColor Red
        Write-Host "    This allows NTLMv1 and/or LM authentication" -ForegroundColor Red
        Write-Host "    Risk: Vulnerable to relay attacks and hash cracking`n" -ForegroundColor Red
        return $false
    }

    $level = $lmLevel.LmCompatibilityLevel
    Write-Host "Current LM Authentication Level: $level" -ForegroundColor Yellow

    switch ($level) {
        0 { 
            Write-Host "[!] VULNERABLE: Send LM & NTLM responses" -ForegroundColor Red
            Write-Host "    Risk: All legacy protocols enabled - CRITICAL vulnerability`n" -ForegroundColor Red
            return $false
        }
        1 { 
            Write-Host "[!] VULNERABLE: Send LM & NTLM with NTLMv2 session security" -ForegroundColor Red
            Write-Host "    Risk: Legacy protocols still enabled`n" -ForegroundColor Red
            return $false
        }
        2 { 
            Write-Host "[!] VULNERABLE: Send NTLM response only" -ForegroundColor Red
            Write-Host "    Risk: NTLMv1 still enabled`n" -ForegroundColor Red
            return $false
        }
        3 { 
            Write-Host "[!] VULNERABLE: Send NTLMv2 response only" -ForegroundColor Red
            Write-Host "    Risk: Will accept LM & NTLM from clients`n" -ForegroundColor Red
            return $false
        }
        4 { 
            Write-Host "[!] VULNERABLE: Send NTLMv2 only, refuse LM" -ForegroundColor Red
            Write-Host "    Risk: Still accepts NTLM responses`n" -ForegroundColor Red
            return $false
        }
        5 { 
            Write-Host "[+] SECURE: Send NTLMv2 only, refuse LM & NTLM" -ForegroundColor Green
            Write-Host "    Configuration is secure`n" -ForegroundColor Green
            return $true
        }
        default {
            Write-Host "[!] UNKNOWN: Unexpected value $level" -ForegroundColor Red
            return $null
        }
    }
}
catch {
    Write-Host "[!] ERROR: Failed to check NTLMv1 authentication status" -ForegroundColor Red
    Write-Host "    $_" -ForegroundColor Red
    return $null
}
