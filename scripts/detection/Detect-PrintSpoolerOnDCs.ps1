<#
.SYNOPSIS
    Detects if Print Spooler service is running on Domain Controllers.

.DESCRIPTION
    This script checks if the Print Spooler service is active on Domain Controllers.
    The Print Spooler service is unnecessary on DCs and has known critical
    vulnerabilities (CVE-2021-34527 PrintNightmare).

.PARAMETER DomainController
    Specific DC to check. If not specified, checks all DCs in the domain.

.EXAMPLE
    .\Detect-PrintSpoolerOnDCs.ps1
    Checks all Domain Controllers in the domain.

.EXAMPLE
    .\Detect-PrintSpoolerOnDCs.ps1 -DomainController "DC01"
    Checks the specified Domain Controller.

.NOTES
    Author: Active Directory Hardening Project
    Reference: Project_Plan_and_Structure.md - Section 6.1 H-04
    CVE: CVE-2021-34527 (PrintNightmare)
    MITRE ATT&CK: T1187 (Forced Authentication)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$DomainController
)

try {
    Write-Host "`n=== Print Spooler Service Detection on DCs ===" -ForegroundColor Cyan
    Write-Host "Checking Print Spooler service status...`n" -ForegroundColor White

    # Get Domain Controllers
    if ($DomainController) {
        $DCs = @($DomainController)
    } else {
        $DCs = (Get-ADDomainController -Filter *).Name
    }

    Write-Host "Checking $($DCs.Count) Domain Controller(s)...`n" -ForegroundColor Yellow

    $vulnerableDCs = @()
    $results = @()

    foreach ($dc in $DCs) {
        Write-Host "Checking $dc..." -ForegroundColor White
        try {
            $spooler = Get-Service -Name Spooler -ComputerName $dc -ErrorAction Stop
            
            $result = [PSCustomObject]@{
                DomainController = $dc
                Status = $spooler.Status
                StartType = $spooler.StartType
                Vulnerable = ($spooler.Status -eq 'Running' -or $spooler.StartType -ne 'Disabled')
            }
            
            $results += $result

            if ($result.Vulnerable) {
                $vulnerableDCs += $dc
                Write-Host "  [!] VULNERABLE: Status=$($spooler.Status), StartType=$($spooler.StartType)" -ForegroundColor Red
            } else {
                Write-Host "  [+] SECURE: Status=$($spooler.Status), StartType=$($spooler.StartType)" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "  [!] ERROR: Unable to check service - $_" -ForegroundColor Red
        }
    }

    # Display summary
    Write-Host "`n=== Detection Summary ===" -ForegroundColor Cyan
    $results | Format-Table -AutoSize

    if ($vulnerableDCs.Count -gt 0) {
        Write-Host "[!] VULNERABLE: Print Spooler is active on $($vulnerableDCs.Count) DC(s)" -ForegroundColor Red
        Write-Host "    Affected DCs: $($vulnerableDCs -join ', ')" -ForegroundColor Red
        Write-Host "    Risk: Unnecessary service with known critical vulnerabilities (PrintNightmare)`n" -ForegroundColor Red
        return $false
    } else {
        Write-Host "[+] SECURE: Print Spooler is disabled on all Domain Controllers" -ForegroundColor Green
        return $true
    }
}
catch {
    Write-Host "[!] ERROR: Failed to check Print Spooler service" -ForegroundColor Red
    Write-Host "    $_" -ForegroundColor Red
    return $null
}
