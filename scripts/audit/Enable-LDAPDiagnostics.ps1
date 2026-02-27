<#
.SYNOPSIS
    Enables LDAP diagnostics for monitoring unsigned LDAP binds.

.DESCRIPTION
    This script enables LDAP interface event logging on Domain Controllers
    to identify clients making unsigned LDAP connections. This is critical
    before enforcing LDAP signing.

.PARAMETER DomainController
    Specific DC to configure. If not specified, configures all DCs.

.EXAMPLE
    .\Enable-LDAPDiagnostics.ps1
    Enables LDAP diagnostics on all Domain Controllers.

.EXAMPLE
    .\Enable-LDAPDiagnostics.ps1 -DomainController "DC01"
    Enables LDAP diagnostics on DC01.

.NOTES
    Author: Active Directory Hardening Project
    Reference: Project_Plan_and_Structure.md - Section 5.4.1
    
    Monitor Event ID 2889 (Directory Service log) for unsigned LDAP binds
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$DomainController
)

try {
    Write-Host "`n=== Enable LDAP Diagnostics ===" -ForegroundColor Cyan
    Write-Host "Enabling LDAP interface event logging...`n" -ForegroundColor White

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
                # Enable LDAP Interface Events (Level 2 = verbose)
                reg add "HKLM\System\CurrentControlSet\Services\NTDS\Diagnostics" `
                    /v "16 LDAP Interface Events" /t REG_DWORD /d 2 /f | Out-Null
                
                Write-Host "  [+] LDAP diagnostics enabled (Level 2)" -ForegroundColor Green
                Write-Host "  [+] Monitor Event ID 2889 in Directory Service log" -ForegroundColor Green
            }
            
            Write-Host "  [+] Successfully configured $dc`n" -ForegroundColor Green
        }
        catch {
            Write-Host "  [!] ERROR: Failed to configure $dc - $_" -ForegroundColor Red
        }
    }

    Write-Host "`n=== Next Steps ===" -ForegroundColor Cyan
    Write-Host "1. Wait 48-72 hours for audit data collection" -ForegroundColor Yellow
    Write-Host "2. Review Event Viewer (Directory Service log, Event ID 2889)" -ForegroundColor Yellow
    Write-Host "3. Identify clients not supporting LDAP signing" -ForegroundColor Yellow
    Write-Host "4. Update or configure applications for LDAP signing" -ForegroundColor Yellow
    Write-Host "5. Enforce LDAP signing after compatibility confirmed`n" -ForegroundColor Yellow

    Write-Host "To view unsigned LDAP events, run:" -ForegroundColor Cyan
    Write-Host "Get-WinEvent -FilterHashtable @{LogName='Directory Service';ID=2889}`n" -ForegroundColor White
}
catch {
    Write-Host "[!] ERROR: Failed to enable LDAP diagnostics" -ForegroundColor Red
    Write-Host "    $_" -ForegroundColor Red
    exit 1
}
