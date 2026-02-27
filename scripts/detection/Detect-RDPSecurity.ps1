<#
.SYNOPSIS
    Detects RDP security configuration.

.DESCRIPTION
    This script checks Remote Desktop Protocol (RDP) security settings including
    Network Level Authentication (NLA), encryption level, and Restricted Admin mode.

.PARAMETER ComputerName
    The computer to check. Defaults to local computer.

.EXAMPLE
    .\Detect-RDPSecurity.ps1
    Checks RDP security on local computer.

.EXAMPLE
    .\Detect-RDPSecurity.ps1 -ComputerName "Server01"
    Checks RDP security on specified computer.

.NOTES
    Author: Active Directory Hardening Project
    Reference: Project_Plan_and_Structure.md - Section 5.6.1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerName = $env:COMPUTERNAME
)

try {
    Write-Host "`n=== RDP Security Configuration Detection ===" -ForegroundColor Cyan
    Write-Host "Checking RDP settings on $ComputerName...`n" -ForegroundColor White

    $scriptBlock = {
        $results = @{}
        
        # Check if RDP is enabled
        $rdpEnabled = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
        $results.RDPEnabled = ($rdpEnabled.fDenyTSConnections -eq 0)
        
        # Check NLA requirement
        $nla = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
        $results.NLA = $nla.UserAuthentication
        
        # Check encryption level
        $encryption = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue
        $results.EncryptionLevel = $encryption.MinEncryptionLevel
        
        # Check Restricted Admin mode
        $restrictedAdmin = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -ErrorAction SilentlyContinue
        $results.RestrictedAdminEnabled = if ($null -eq $restrictedAdmin) { $false } else { $restrictedAdmin.DisableRestrictedAdmin -eq 0 }
        
        return $results
    }

    if ($ComputerName -eq $env:COMPUTERNAME) {
        $config = & $scriptBlock
    } else {
        $config = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock
    }

    $issues = @()

    Write-Host "RDP Configuration:" -ForegroundColor Yellow
    Write-Host "==================" -ForegroundColor Yellow
    
    # RDP Status
    if ($config.RDPEnabled) {
        Write-Host "  RDP Status: Enabled" -ForegroundColor Yellow
    } else {
        Write-Host "  RDP Status: Disabled" -ForegroundColor Green
    }

    if ($config.RDPEnabled) {
        # NLA Check
        if ($config.NLA -eq 1) {
            Write-Host "  [+] Network Level Authentication: Enabled" -ForegroundColor Green
        } else {
            Write-Host "  [!] Network Level Authentication: Disabled" -ForegroundColor Red
            $issues += "NLA not enabled"
        }

        # Encryption Level Check
        $encryptionStatus = switch ($config.EncryptionLevel) {
            1 { "Low"; $true }
            2 { "Client Compatible"; $true }
            3 { "High"; $false }
            4 { "FIPS Compliant"; $false }
            default { "Not Set"; $true }
        }
        
        if ($encryptionStatus[1]) {
            Write-Host "  [!] Encryption Level: $($encryptionStatus[0])" -ForegroundColor Red
            $issues += "Weak encryption level"
        } else {
            Write-Host "  [+] Encryption Level: $($encryptionStatus[0])" -ForegroundColor Green
        }

        # Restricted Admin Mode Check
        if ($config.RestrictedAdminEnabled) {
            Write-Host "  [+] Restricted Admin Mode: Enabled" -ForegroundColor Green
        } else {
            Write-Host "  [!] Restricted Admin Mode: Disabled" -ForegroundColor Yellow
            $issues += "Restricted Admin mode not enabled"
        }
    }

    Write-Host ""
    if ($issues.Count -gt 0) {
        Write-Host "[!] VULNERABLE: RDP security issues detected" -ForegroundColor Red
        foreach ($issue in $issues) {
            Write-Host "    - $issue" -ForegroundColor Red
        }
        Write-Host ""
        return $false
    } elseif ($config.RDPEnabled) {
        Write-Host "[+] SECURE: RDP security is properly configured" -ForegroundColor Green
        return $true
    } else {
        Write-Host "[+] INFO: RDP is disabled" -ForegroundColor Green
        return $true
    }
}
catch {
    Write-Host "[!] ERROR: Failed to check RDP security configuration" -ForegroundColor Red
    Write-Host "    $_" -ForegroundColor Red
    return $null
}
