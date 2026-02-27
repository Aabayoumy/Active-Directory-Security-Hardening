<#
.SYNOPSIS
    Detects weak password policy configuration in Active Directory domain.

.DESCRIPTION
    This script checks the current domain password policy settings to identify
    weak configurations that may expose the organization to brute force attacks.
    Specifically checks for minimum password length below recommended standards.

.PARAMETER Domain
    The domain to check. Defaults to current domain.

.EXAMPLE
    .\Detect-WeakPasswordPolicy.ps1
    Checks the default domain password policy.

.EXAMPLE
    .\Detect-WeakPasswordPolicy.ps1 -Domain "contoso.com"
    Checks password policy for the specified domain.

.NOTES
    Author: Active Directory Hardening Project
    Reference: Project_Plan_and_Structure.md - Section 4.4 H-01
    ISO 27001: Controls 5.17, 5.18
    MITRE ATT&CK: T1201 (Password Policy Discovery)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Domain
)

try {
    Write-Host "`n=== Weak Password Policy Detection ===" -ForegroundColor Cyan
    Write-Host "Checking domain password policy configuration...`n" -ForegroundColor White

    # Get the default domain password policy
    if ($Domain) {
        $policy = Get-ADDefaultDomainPasswordPolicy -Identity $Domain -ErrorAction Stop
    } else {
        $policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    }

    # Display current settings
    Write-Host "Current Password Policy Settings:" -ForegroundColor Yellow
    Write-Host "=================================" -ForegroundColor Yellow
    $policy | Select-Object MinPasswordLength, PasswordHistoryCount, ComplexityEnabled, MaxPasswordAge | Format-List

    # Check for weak password length
    if ($policy.MinPasswordLength -lt 12) {
        Write-Host "[!] VULNERABLE: Minimum password length is $($policy.MinPasswordLength) characters" -ForegroundColor Red
        Write-Host "    Recommended: Minimum 12 characters" -ForegroundColor Yellow
        Write-Host "    Risk: Susceptible to brute force and dictionary attacks`n" -ForegroundColor Red
        return $false
    } else {
        Write-Host "[+] SECURE: Minimum password length meets requirements ($($policy.MinPasswordLength) characters)" -ForegroundColor Green
        return $true
    }
}
catch {
    Write-Host "[!] ERROR: Failed to retrieve password policy" -ForegroundColor Red
    Write-Host "    $_" -ForegroundColor Red
    return $null
}
