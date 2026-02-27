<#
.SYNOPSIS
    Enables NTLM auditing to identify systems using NTLM authentication.

.DESCRIPTION
    This script enables NTLM auditing on Domain Controllers to monitor
    which systems and applications are using NTLM authentication.
    This is a critical first step before disabling NTLMv1.

.PARAMETER DomainController
    Specific DC to configure. If not specified, configures all DCs.

.PARAMETER AuditDuration
    Number of hours to audit. Default is 72 hours (3 days).

.EXAMPLE
    .\Enable-NTLMAuditing.ps1
    Enables NTLM auditing on all Domain Controllers.

.EXAMPLE
    .\Enable-NTLMAuditing.ps1 -DomainController "DC01" -AuditDuration 48
    Enables NTLM auditing on DC01 for 48 hours.

.NOTES
    Author: Active Directory Hardening Project
    Reference: Project_Plan_and_Structure.md - Section 5.2.1
    
    Monitor Event ID 4624 (Security log) for NTLM authentication events
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$DomainController,
    
    [Parameter(Mandatory=$false)]
    [int]$AuditDuration = 72
)

try {
    Write-Host "`n=== Enable NTLM Auditing ===" -ForegroundColor Cyan
    Write-Host "Enabling NTLM auditing for $AuditDuration hours...`n" -ForegroundColor White

    # Get Domain Controllers
    if ($DomainController) {
        $DCs = @($DomainController)
    } else {
        $DCs = (Get-ADDomainController -Filter *).Name
    }

    Write-Host "Configuring $($DCs.Count) Domain Controller(s)...`n" -ForegroundColor Yellow

    foreach ($dc in $DCs) {
        Write-Host "Configuring $dc..." -ForegroundColor White
        try {
            Invoke-Command -ComputerName $dc -ScriptBlock {
                param($hours)
                
                # Enable NTLM auditing (Value 2 = audit both domain and outbound)
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                    -Name "AuditReceivingNTLMTraffic" -Value 2 -PropertyType DWord -Force | Out-Null
                
                Write-Host "  [+] NTLM auditing enabled" -ForegroundColor Green
                Write-Host "  [+] Monitor Event ID 4624 in Security log" -ForegroundColor Green
                Write-Host "  [+] Audit duration: $hours hours" -ForegroundColor Green
                
            } -ArgumentList $AuditDuration
            
            Write-Host "  [+] Successfully configured $dc`n" -ForegroundColor Green
        }
        catch {
            Write-Host "  [!] ERROR: Failed to configure $dc - $_" -ForegroundColor Red
        }
    }

    Write-Host "`n=== Next Steps ===" -ForegroundColor Cyan
    Write-Host "1. Wait $AuditDuration hours for audit data collection" -ForegroundColor Yellow
    Write-Host "2. Review Event Viewer (Security log, Event ID 4624)" -ForegroundColor Yellow
    Write-Host "3. Look for 'NTLM' in Authentication Package field" -ForegroundColor Yellow
    Write-Host "4. Identify applications/systems using NTLM" -ForegroundColor Yellow
    Write-Host "5. Contact application owners before enforcement`n" -ForegroundColor Yellow

    Write-Host "To view NTLM events, run:" -ForegroundColor Cyan
    Write-Host "Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 1000 | Where-Object {`$_.Message -like '*NTLM*'}`n" -ForegroundColor White
}
catch {
    Write-Host "[!] ERROR: Failed to enable NTLM auditing" -ForegroundColor Red
    Write-Host "    $_" -ForegroundColor Red
    exit 1
}
