<#
.SYNOPSIS
    Detects current audit policy configuration.

.DESCRIPTION
    This script checks the advanced audit policy configuration to determine
    if appropriate security auditing is enabled. Reviews key audit categories
    for Active Directory security monitoring.

.PARAMETER ComputerName
    The computer to check. Defaults to local computer.

.EXAMPLE
    .\Detect-AuditPolicies.ps1
    Checks audit policy on local computer.

.EXAMPLE
    .\Detect-AuditPolicies.ps1 -ComputerName "DC01"
    Checks audit policy on specified computer.

.NOTES
    Author: Active Directory Hardening Project
    Reference: Project_Plan_and_Structure.md - Section 5.4.3 M-01
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerName = $env:COMPUTERNAME
)

try {
    Write-Host "`n=== Audit Policy Detection ===" -ForegroundColor Cyan
    Write-Host "Checking audit policy configuration on $ComputerName...`n" -ForegroundColor White

    $scriptBlock = {
        # Get audit policy for critical categories
        $auditOutput = auditpol /get /category:* 2>&1
        return $auditOutput
    }

    if ($ComputerName -eq $env:COMPUTERNAME) {
        $auditPolicy = & $scriptBlock
    } else {
        $auditPolicy = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock
    }

    # Key audit subcategories to check
    $criticalAudits = @{
        "Credential Validation" = $false
        "Kerberos Authentication Service" = $false
        "User Account Management" = $false
        "Security Group Management" = $false
        "Directory Service Changes" = $false
        "Directory Service Access" = $false
        "Audit Policy Change" = $false
        "Sensitive Privilege Use" = $false
        "Process Creation" = $false
    }

    Write-Host "Critical Audit Categories Status:" -ForegroundColor Yellow
    Write-Host "==================================" -ForegroundColor Yellow

    $missingAudits = @()
    
    foreach ($auditName in $criticalAudits.Keys) {
        $auditLine = $auditPolicy | Where-Object { $_ -like "*$auditName*" }
        
        if ($auditLine -and ($auditLine -like "*Success and Failure*" -or $auditLine -like "*Success*")) {
            Write-Host "  [+] $auditName : Enabled" -ForegroundColor Green
            $criticalAudits[$auditName] = $true
        } else {
            Write-Host "  [!] $auditName : Not Enabled" -ForegroundColor Red
            $missingAudits += $auditName
        }
    }

    Write-Host ""
    
    $enabledCount = ($criticalAudits.Values | Where-Object { $_ -eq $true }).Count
    $totalCount = $criticalAudits.Count
    
    Write-Host "Audit Coverage: $enabledCount/$totalCount critical categories enabled" -ForegroundColor Yellow

    if ($missingAudits.Count -gt 0) {
        Write-Host "`n[!] VULNERABLE: Critical audit categories are not enabled" -ForegroundColor Red
        Write-Host "    Missing audits:" -ForegroundColor Red
        foreach ($audit in $missingAudits) {
            Write-Host "      - $audit" -ForegroundColor Red
        }
        Write-Host "    Risk: Insufficient logging for security monitoring and incident response`n" -ForegroundColor Red
        return $false
    } else {
        Write-Host "`n[+] SECURE: All critical audit categories are enabled" -ForegroundColor Green
        return $true
    }
}
catch {
    Write-Host "[!] ERROR: Failed to check audit policy configuration" -ForegroundColor Red
    Write-Host "    $_" -ForegroundColor Red
    return $null
}
