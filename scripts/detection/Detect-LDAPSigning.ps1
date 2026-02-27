<#
.SYNOPSIS
    Detects if LDAP signing is required on Domain Controllers.

.DESCRIPTION
    This script checks the LDAPServerIntegrity registry setting to determine
    if LDAP signing is required. Unsigned LDAP traffic is vulnerable to
    man-in-the-middle attacks.

.PARAMETER DomainController
    Specific DC to check. If not specified, checks local computer.

.EXAMPLE
    .\Detect-LDAPSigning.ps1
    Checks LDAP signing requirement on local computer.

.EXAMPLE
    .\Detect-LDAPSigning.ps1 -DomainController "DC01"
    Checks LDAP signing requirement on specified DC.

.NOTES
    Author: Active Directory Hardening Project
    Reference: Project_Plan_and_Structure.md - Section 5.4.1 M-03
    
    LDAPServerIntegrity values:
    0 or not set = None (unsigned allowed)
    1 = Negotiate signing
    2 = Require signing
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$DomainController
)

try {
    Write-Host "`n=== LDAP Signing Detection ===" -ForegroundColor Cyan
    
    $computerName = if ($DomainController) { $DomainController } else { $env:COMPUTERNAME }
    Write-Host "Checking LDAP signing requirement on $computerName...`n" -ForegroundColor White

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    $regName = "LDAPServerIntegrity"

    if ($DomainController -and $DomainController -ne $env:COMPUTERNAME) {
        $ldapIntegrity = Invoke-Command -ComputerName $DomainController -ScriptBlock {
            Get-ItemProperty -Path $using:regPath -Name $using:regName -ErrorAction SilentlyContinue
        }
    } else {
        $ldapIntegrity = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
    }

    if ($null -eq $ldapIntegrity) {
        Write-Host "[!] VULNERABLE: LDAPServerIntegrity not set" -ForegroundColor Red
        Write-Host "    Current setting: Not configured (allows unsigned LDAP)" -ForegroundColor Red
        Write-Host "    Risk: LDAP traffic vulnerable to man-in-the-middle attacks`n" -ForegroundColor Red
        return $false
    }

    $value = $ldapIntegrity.LDAPServerIntegrity
    Write-Host "Current LDAPServerIntegrity value: $value" -ForegroundColor Yellow

    switch ($value) {
        0 { 
            Write-Host "[!] VULNERABLE: LDAP signing not required" -ForegroundColor Red
            Write-Host "    Risk: Unsigned LDAP traffic allowed`n" -ForegroundColor Red
            return $false
        }
        1 { 
            Write-Host "[!] WARNING: LDAP signing negotiated (not required)" -ForegroundColor Yellow
            Write-Host "    Risk: Clients can connect without signing" -ForegroundColor Yellow
            Write-Host "    Recommendation: Set to 2 (require signing)`n" -ForegroundColor Yellow
            return $false
        }
        2 { 
            Write-Host "[+] SECURE: LDAP signing required" -ForegroundColor Green
            Write-Host "    All LDAP connections must be signed`n" -ForegroundColor Green
            return $true
        }
        default {
            Write-Host "[!] UNKNOWN: Unexpected value $value" -ForegroundColor Red
            return $null
        }
    }
}
catch {
    Write-Host "[!] ERROR: Failed to check LDAP signing configuration" -ForegroundColor Red
    Write-Host "    $_" -ForegroundColor Red
    return $null
}
