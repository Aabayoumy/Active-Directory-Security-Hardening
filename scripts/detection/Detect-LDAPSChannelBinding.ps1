<#
.SYNOPSIS
    Detects if LDAPS channel binding is enforced.

.DESCRIPTION
    This script checks the LdapEnforceChannelBinding registry setting to
    determine if LDAPS channel binding is enforced. Channel binding provides
    additional security for LDAPS connections.

.PARAMETER DomainController
    Specific DC to check. If not specified, checks local computer.

.EXAMPLE
    .\Detect-LDAPSChannelBinding.ps1
    Checks LDAPS channel binding on local computer.

.EXAMPLE
    .\Detect-LDAPSChannelBinding.ps1 -DomainController "DC01"
    Checks LDAPS channel binding on specified DC.

.NOTES
    Author: Active Directory Hardening Project
    Reference: Project_Plan_and_Structure.md - Section 5.4.2 M-02
    
    LdapEnforceChannelBinding values:
    0 or not set = Never
    1 = When supported
    2 = Always
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$DomainController
)

try {
    Write-Host "`n=== LDAPS Channel Binding Detection ===" -ForegroundColor Cyan
    
    $computerName = if ($DomainController) { $DomainController } else { $env:COMPUTERNAME }
    Write-Host "Checking LDAPS channel binding on $computerName...`n" -ForegroundColor White

    $regPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"
    $regName = "LdapEnforceChannelBinding"

    if ($DomainController -and $DomainController -ne $env:COMPUTERNAME) {
        $channelBinding = Invoke-Command -ComputerName $DomainController -ScriptBlock {
            Get-ItemProperty -Path $using:regPath -Name $using:regName -ErrorAction SilentlyContinue
        }
    } else {
        $channelBinding = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
    }

    if ($null -eq $channelBinding) {
        Write-Host "[!] VULNERABLE: LdapEnforceChannelBinding not set" -ForegroundColor Red
        Write-Host "    Current setting: Not configured (channel binding not enforced)" -ForegroundColor Red
        Write-Host "    Risk: LDAPS connections lack additional security protection`n" -ForegroundColor Red
        return $false
    }

    $value = $channelBinding.LdapEnforceChannelBinding
    Write-Host "Current LdapEnforceChannelBinding value: $value" -ForegroundColor Yellow

    switch ($value) {
        0 { 
            Write-Host "[!] VULNERABLE: Channel binding never enforced" -ForegroundColor Red
            Write-Host "    Risk: LDAPS connections without channel binding protection`n" -ForegroundColor Red
            return $false
        }
        1 { 
            Write-Host "[!] WARNING: Channel binding when supported" -ForegroundColor Yellow
            Write-Host "    Status: Enforced only when client supports it" -ForegroundColor Yellow
            Write-Host "    Recommendation: Consider value 2 (always) for maximum security`n" -ForegroundColor Yellow
            return $true  # This is acceptable for most environments
        }
        2 { 
            Write-Host "[+] SECURE: Channel binding always enforced" -ForegroundColor Green
            Write-Host "    All LDAPS connections require channel binding`n" -ForegroundColor Green
            return $true
        }
        default {
            Write-Host "[!] UNKNOWN: Unexpected value $value" -ForegroundColor Red
            return $null
        }
    }
}
catch {
    Write-Host "[!] ERROR: Failed to check LDAPS channel binding" -ForegroundColor Red
    Write-Host "    $_" -ForegroundColor Red
    return $null
}
