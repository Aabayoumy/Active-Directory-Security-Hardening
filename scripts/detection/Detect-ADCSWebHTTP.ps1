<#
.SYNOPSIS
    Detects if ADCS Web Enrollment uses HTTP (insecure).

.DESCRIPTION
    This script checks IIS bindings on the Certificate Authority server
    to determine if HTTP is enabled for certificate enrollment.
    HTTP certificate enrollment exposes credentials in clear text.

.PARAMETER CAServer
    The Certificate Authority server to check. Defaults to local computer.

.EXAMPLE
    .\Detect-ADCSWebHTTP.ps1
    Checks the local CA server for HTTP bindings.

.EXAMPLE
    .\Detect-ADCSWebHTTP.ps1 -CAServer "CA01"
    Checks the specified CA server.

.NOTES
    Author: Active Directory Hardening Project
    Reference: Project_Plan_and_Structure.md - Section 5.4.3 M-04
    
    Requires: WebAdministration module
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$CAServer = $env:COMPUTERNAME
)

try {
    Write-Host "`n=== ADCS Web Enrollment HTTP Detection ===" -ForegroundColor Cyan
    Write-Host "Checking IIS bindings on $CAServer...`n" -ForegroundColor White

    $scriptBlock = {
        # Import WebAdministration module
        Import-Module WebAdministration -ErrorAction Stop

        # Check for HTTP bindings related to CertSrv
        $httpBindings = Get-WebBinding -Protocol "http" | Where-Object { 
            $_.bindingInformation -like "*certsrv*" -or 
            (Get-WebApplication -Site $_.ItemXPath.Split("'")[1] | Where-Object { $_.Path -eq "/certsrv" })
        }

        # Also check all HTTP bindings on Default Web Site (where CertSrv typically runs)
        $allHttpBindings = Get-WebBinding -Name "Default Web Site" -Protocol "http"

        return @{
            CertSrvHttpBindings = $httpBindings
            AllHttpBindings = $allHttpBindings
        }
    }

    if ($CAServer -eq $env:COMPUTERNAME) {
        $result = & $scriptBlock
    } else {
        $result = Invoke-Command -ComputerName $CAServer -ScriptBlock $scriptBlock
    }

    if ($result.AllHttpBindings) {
        Write-Host "[!] VULNERABLE: HTTP bindings found on CA server" -ForegroundColor Red
        Write-Host "`nHTTP Bindings:" -ForegroundColor Yellow
        $result.AllHttpBindings | ForEach-Object {
            Write-Host "  - $($_.protocol)://$($_.bindingInformation)" -ForegroundColor Red
        }
        Write-Host "`n    Risk: Certificate enrollment over HTTP exposes credentials" -ForegroundColor Red
        Write-Host "    Recommendation: Remove HTTP bindings, enforce HTTPS only`n" -ForegroundColor Red
        return $false
    } else {
        Write-Host "[+] SECURE: No HTTP bindings found" -ForegroundColor Green
        Write-Host "    ADCS Web Enrollment is using HTTPS only`n" -ForegroundColor Green
        return $true
    }
}
catch {
    Write-Host "[!] ERROR: Failed to check ADCS Web Enrollment configuration" -ForegroundColor Red
    Write-Host "    $_" -ForegroundColor Red
    Write-Host "    Note: Ensure WebAdministration module is available`n" -ForegroundColor Yellow
    return $null
}
