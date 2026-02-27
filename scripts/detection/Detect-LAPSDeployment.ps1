<#
.SYNOPSIS
    Detects if Windows LAPS (Local Administrator Password Solution) is deployed.

.DESCRIPTION
    This script checks for Windows LAPS configuration in the environment.
    Windows LAPS is built-in to Windows Server 2022 and Windows 11.
    Checks for registry settings, AD schema attributes, and computers with
    LAPS passwords stored.

.EXAMPLE
    .\Detect-LAPSDeployment.ps1
    Checks for Windows LAPS deployment in the domain.

.NOTES
    Author: Active Directory Hardening Project
    Reference: Project_Plan_and_Structure.md - Section 5.3.1 H-03
    ISO 27001: Controls 5.17, 5.18
    MITRE ATT&CK: T1078.003 (Valid Accounts: Local)
    
    Note: This checks for native Windows LAPS, not legacy Microsoft LAPS
#>

[CmdletBinding()]
param()

try {
    Write-Host "`n=== Windows LAPS Deployment Detection ===" -ForegroundColor Cyan
    Write-Host "Checking for Windows LAPS configuration...`n" -ForegroundColor White

    $lapsDeployed = $false
    $findings = @()

    # Check 1: Registry settings for Windows LAPS
    Write-Host "[*] Checking registry for Windows LAPS policy..." -ForegroundColor Yellow
    $lapsRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
    $lapsReg = Get-ItemProperty -Path $lapsRegPath -ErrorAction SilentlyContinue

    if ($lapsReg) {
        Write-Host "    [+] LAPS registry key found" -ForegroundColor Green
        $findings += "Registry configuration exists"
        $lapsDeployed = $true
    } else {
        Write-Host "    [-] LAPS registry key not found" -ForegroundColor Red
        $findings += "No registry configuration"
    }

    # Check 2: AD Schema for Windows LAPS attributes
    Write-Host "[*] Checking AD schema for LAPS attributes..." -ForegroundColor Yellow
    try {
        $domain = Get-ADDomain
        $schemaPath = "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,$($domain.DistinguishedName -replace '^DC=.*','DC=' + ($domain.Forest -replace '\.',',DC='))"
        $schemaAttr = Get-ADObject $schemaPath -ErrorAction SilentlyContinue

        if ($schemaAttr) {
            Write-Host "    [+] LAPS schema attribute found" -ForegroundColor Green
            $findings += "AD schema configured"
            $lapsDeployed = $true
        } else {
            Write-Host "    [-] LAPS schema attribute not found" -ForegroundColor Red
            $findings += "AD schema not configured"
        }
    }
    catch {
        Write-Host "    [!] Unable to check AD schema: $_" -ForegroundColor Yellow
    }

    # Check 3: Computers with LAPS passwords
    Write-Host "[*] Checking for computers with LAPS passwords..." -ForegroundColor Yellow
    try {
        $lapsComputers = Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd -ErrorAction SilentlyContinue | 
            Where-Object { $_."ms-Mcs-AdmPwd" -ne $null }

        if ($lapsComputers) {
            $count = ($lapsComputers | Measure-Object).Count
            Write-Host "    [+] Found $count computer(s) with LAPS passwords" -ForegroundColor Green
            $findings += "$count computers managed by LAPS"
            $lapsDeployed = $true
        } else {
            Write-Host "    [-] No computers with LAPS passwords found" -ForegroundColor Red
            $findings += "No computers managed by LAPS"
        }
    }
    catch {
        Write-Host "    [!] Unable to query computers: $_" -ForegroundColor Yellow
    }

    # Summary
    Write-Host "`n=== Detection Summary ===" -ForegroundColor Cyan
    $findings | ForEach-Object { Write-Host "  - $_" -ForegroundColor White }

    if ($lapsDeployed) {
        Write-Host "`n[+] SECURE: Windows LAPS appears to be deployed" -ForegroundColor Green
        return $true
    } else {
        Write-Host "`n[!] VULNERABLE: Windows LAPS is NOT deployed" -ForegroundColor Red
        Write-Host "    Risk: Static local admin passwords enable lateral movement`n" -ForegroundColor Red
        return $false
    }
}
catch {
    Write-Host "[!] ERROR: Failed to detect LAPS deployment" -ForegroundColor Red
    Write-Host "    $_" -ForegroundColor Red
    return $null
}
