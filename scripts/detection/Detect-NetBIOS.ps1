<#
.SYNOPSIS
    Detects if NetBIOS over TCP/IP is enabled.

.DESCRIPTION
    This script checks the NetBIOS over TCP/IP configuration on network adapters.
    NetBIOS is a legacy protocol vulnerable to name poisoning attacks and should
    be disabled in modern environments.

.PARAMETER ComputerName
    The computer to check. Defaults to local computer.

.EXAMPLE
    .\Detect-NetBIOS.ps1
    Checks NetBIOS status on local computer.

.EXAMPLE
    .\Detect-NetBIOS.ps1 -ComputerName "WS01"
    Checks NetBIOS status on specified computer.

.NOTES
    Author: Active Directory Hardening Project
    Reference: Project_Plan_and_Structure.md - Section 5.5.2
    
    TcpipNetbiosOptions values:
    0 = Default (use DHCP setting, usually enabled)
    1 = Enabled
    2 = Disabled
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerName = $env:COMPUTERNAME
)

try {
    Write-Host "`n=== NetBIOS over TCP/IP Detection ===" -ForegroundColor Cyan
    Write-Host "Checking NetBIOS status on $ComputerName...`n" -ForegroundColor White

    $scriptBlock = {
        Get-WmiObject Win32_NetworkAdapterConfiguration | 
            Where-Object { $_.IPEnabled -eq $true } | 
            Select-Object Description, TcpipNetbiosOptions
    }

    if ($ComputerName -eq $env:COMPUTERNAME) {
        $adapters = & $scriptBlock
    } else {
        $adapters = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock
    }

    if (-not $adapters) {
        Write-Host "[!] WARNING: No enabled network adapters found" -ForegroundColor Yellow
        return $null
    }

    Write-Host "Network Adapter NetBIOS Configuration:" -ForegroundColor Yellow
    Write-Host "=======================================" -ForegroundColor Yellow

    $vulnerable = $false
    foreach ($adapter in $adapters) {
        $status = switch ($adapter.TcpipNetbiosOptions) {
            0 { "Default (usually enabled)"; $vulnerable = $true }
            1 { "Enabled"; $vulnerable = $true }
            2 { "Disabled" }
            default { "Unknown" }
        }

        $color = if ($adapter.TcpipNetbiosOptions -eq 2) { "Green" } else { "Red" }
        Write-Host "  $($adapter.Description)" -ForegroundColor White
        Write-Host "    NetBIOS: $status (value: $($adapter.TcpipNetbiosOptions))" -ForegroundColor $color
    }

    Write-Host ""
    if ($vulnerable) {
        Write-Host "[!] VULNERABLE: NetBIOS over TCP/IP is enabled on one or more adapters" -ForegroundColor Red
        Write-Host "    Risk: Vulnerable to NetBIOS poisoning and credential theft" -ForegroundColor Red
        Write-Host "    Recommendation: Set TcpipNetbiosOptions to 2 (Disabled) on all adapters`n" -ForegroundColor Red
        return $false
    } else {
        Write-Host "[+] SECURE: NetBIOS over TCP/IP is disabled on all adapters" -ForegroundColor Green
        return $true
    }
}
catch {
    Write-Host "[!] ERROR: Failed to check NetBIOS status" -ForegroundColor Red
    Write-Host "    $_" -ForegroundColor Red
    return $null
}
