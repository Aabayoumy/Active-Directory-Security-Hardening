<#
.SYNOPSIS
    Detects if Active Directory Recycle Bin is enabled.

.DESCRIPTION
    This script checks if the AD Recycle Bin optional feature is enabled.
    The Recycle Bin provides the ability to recover deleted AD objects
    without requiring authoritative restore from backup.

.EXAMPLE
    .\Detect-ADRecycleBin.ps1
    Checks if AD Recycle Bin is enabled in the forest.

.NOTES
    Author: Active Directory Hardening Project
    Reference: Project_Plan_and_Structure.md - Section 5.5.1 L-01
    
    Note: Requires Windows Server 2008 R2 forest functional level or higher
#>

[CmdletBinding()]
param()

try {
    Write-Host "`n=== AD Recycle Bin Detection ===" -ForegroundColor Cyan
    Write-Host "Checking AD Recycle Bin status...`n" -ForegroundColor White

    # Get forest information
    $forest = Get-ADForest
    Write-Host "Forest: $($forest.Name)" -ForegroundColor White
    Write-Host "Forest Functional Level: $($forest.ForestMode)" -ForegroundColor White

    # Check forest functional level
    $forestModeValue = [int]$forest.ForestMode
    # Windows2008R2Forest = 4
    if ($forestModeValue -lt 4) {
        Write-Host "`n[!] WARNING: Forest functional level is too low for AD Recycle Bin" -ForegroundColor Yellow
        Write-Host "    Required: Windows Server 2008 R2 or higher" -ForegroundColor Yellow
        Write-Host "    Current: $($forest.ForestMode)" -ForegroundColor Yellow
        Write-Host "    Action: Raise forest functional level before enabling Recycle Bin`n" -ForegroundColor Yellow
        return $null
    }

    # Check if Recycle Bin is enabled
    $recycleBin = Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"' -ErrorAction Stop
    $enabledScopes = $recycleBin.EnabledScopes

    Write-Host "`nRecycle Bin Feature Information:" -ForegroundColor Yellow
    Write-Host "================================" -ForegroundColor Yellow
    Write-Host "  Feature Name: $($recycleBin.Name)" -ForegroundColor White
    Write-Host "  Required Forest Mode: $($recycleBin.RequiredForestMode)" -ForegroundColor White

    if ($enabledScopes.Count -gt 0) {
        Write-Host "`n[+] ENABLED: AD Recycle Bin is enabled" -ForegroundColor Green
        Write-Host "    Enabled Scopes:" -ForegroundColor Green
        foreach ($scope in $enabledScopes) {
            Write-Host "      - $scope" -ForegroundColor Green
        }
        Write-Host ""
        return $true
    } else {
        Write-Host "`n[!] DISABLED: AD Recycle Bin is not enabled" -ForegroundColor Red
        Write-Host "    Impact: Limited recovery options for deleted AD objects" -ForegroundColor Red
        Write-Host "    Risk: Must use authoritative restore from backup to recover deleted objects" -ForegroundColor Red
        Write-Host "    Note: Enabling is irreversible operation`n" -ForegroundColor Yellow
        return $false
    }
}
catch {
    Write-Host "[!] ERROR: Failed to check AD Recycle Bin status" -ForegroundColor Red
    Write-Host "    $_" -ForegroundColor Red
    return $null
}
