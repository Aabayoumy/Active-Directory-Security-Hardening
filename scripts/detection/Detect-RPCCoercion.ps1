<#
.SYNOPSIS
    Detects RPC coercion vulnerability configuration.

.DESCRIPTION
    This script checks if NTLM outbound traffic restrictions are configured
    on Domain Controllers to mitigate RPC coercion attacks (PetitPotam).
    RPC coercion can force DC authentication, enabling ADCS attacks.

.PARAMETER DomainController
    Specific DC to check. If not specified, checks local computer.

.EXAMPLE
    .\Detect-RPCCoercion.ps1
    Checks the local computer for RPC coercion mitigation.

.EXAMPLE
    .\Detect-RPCCoercion.ps1 -DomainController "DC01"
    Checks the specified Domain Controller.

.NOTES
    Author: Active Directory Hardening Project
    Reference: Project_Plan_and_Structure.md - Section 5.3.2 H-05
    CVE: CVE-2021-36942 (PetitPotam)
    MITRE ATT&CK: T1187 (Forced Authentication)
    
    RestrictSendingNTLMTraffic values:
    0 or not set = Allow all
    1 = Audit
    2 = Block
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$DomainController
)

try {
    Write-Host "`n=== RPC Coercion Vulnerability Detection ===" -ForegroundColor Cyan
    
    $computerName = if ($DomainController) { $DomainController } else { $env:COMPUTERNAME }
    Write-Host "Checking NTLM outbound restrictions on $computerName...`n" -ForegroundColor White

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    $regName = "RestrictSendingNTLMTraffic"

    if ($DomainController -and $DomainController -ne $env:COMPUTERNAME) {
        $ntlmRestriction = Invoke-Command -ComputerName $DomainController -ScriptBlock {
            Get-ItemProperty -Path $using:regPath -Name $using:regName -ErrorAction SilentlyContinue
        }
    } else {
        $ntlmRestriction = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
    }

    if ($null -eq $ntlmRestriction) {
        Write-Host "[!] VULNERABLE: RestrictSendingNTLMTraffic not configured" -ForegroundColor Red
        Write-Host "    Current setting: Not set (allows all NTLM outbound)" -ForegroundColor Red
        Write-Host "    Risk: DC can be forced to authenticate, enabling ADCS attacks`n" -ForegroundColor Red
        return $false
    }

    $value = $ntlmRestriction.RestrictSendingNTLMTraffic
    Write-Host "Current RestrictSendingNTLMTraffic value: $value" -ForegroundColor Yellow

    switch ($value) {
        0 { 
            Write-Host "[!] VULNERABLE: Allow all NTLM outbound traffic" -ForegroundColor Red
            Write-Host "    Risk: DC can be coerced to authenticate to attacker`n" -ForegroundColor Red
            return $false
        }
        1 { 
            Write-Host "[!] WARNING: Audit mode enabled (not blocking)" -ForegroundColor Yellow
            Write-Host "    Status: Logging NTLM outbound attempts but not blocking" -ForegroundColor Yellow
            Write-Host "    Action: Review audit logs and move to blocking mode`n" -ForegroundColor Yellow
            return $false
        }
        2 { 
            Write-Host "[+] SECURE: Blocking NTLM outbound traffic" -ForegroundColor Green
            Write-Host "    RPC coercion attacks are mitigated`n" -ForegroundColor Green
            return $true
        }
        default {
            Write-Host "[!] UNKNOWN: Unexpected value $value" -ForegroundColor Red
            return $null
        }
    }
}
catch {
    Write-Host "[!] ERROR: Failed to check RPC coercion vulnerability" -ForegroundColor Red
    Write-Host "    $_" -ForegroundColor Red
    return $null
}
