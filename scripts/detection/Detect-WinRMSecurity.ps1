<#
.SYNOPSIS
    Detects WinRM security configuration.

.DESCRIPTION
    This script checks Windows Remote Management (WinRM) security settings including
    listener protocols, trusted hosts configuration, and service status.

.PARAMETER ComputerName
    The computer to check. Defaults to local computer.

.EXAMPLE
    .\Detect-WinRMSecurity.ps1
    Checks WinRM security on local computer.

.EXAMPLE
    .\Detect-WinRMSecurity.ps1 -ComputerName "Server01"
    Checks WinRM security on specified computer.

.NOTES
    Author: Active Directory Hardening Project
    Reference: Project_Plan_and_Structure.md - Section 5.6.2
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerName = $env:COMPUTERNAME
)

try {
    Write-Host "`n=== WinRM Security Configuration Detection ===" -ForegroundColor Cyan
    Write-Host "Checking WinRM settings on $ComputerName...`n" -ForegroundColor White

    $scriptBlock = {
        $results = @{}
        
        # Check WinRM service status
        $service = Get-Service WinRM -ErrorAction SilentlyContinue
        $results.ServiceStatus = $service.Status
        $results.ServiceStartType = $service.StartType
        
        # Check WinRM listeners
        $listeners = Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate -ErrorAction SilentlyContinue
        $results.Listeners = $listeners
        
        # Check for HTTP listener
        $httpListener = Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue | 
            Where-Object { $_.Keys -contains "Transport=HTTP" }
        $results.HTTPListenerExists = ($null -ne $httpListener)
        
        # Check TrustedHosts
        $trustedHosts = Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue
        $results.TrustedHosts = $trustedHosts.Value
        
        return $results
    }

    if ($ComputerName -eq $env:COMPUTERNAME) {
        $config = & $scriptBlock
    } else {
        $config = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock
    }

    $issues = @()

    Write-Host "WinRM Configuration:" -ForegroundColor Yellow
    Write-Host "====================" -ForegroundColor Yellow
    
    # Service Status
    Write-Host "  Service Status: $($config.ServiceStatus)" -ForegroundColor White
    Write-Host "  Start Type: $($config.ServiceStartType)" -ForegroundColor White

    if ($config.ServiceStatus -eq 'Running') {
        # Check for HTTP listener
        if ($config.HTTPListenerExists) {
            Write-Host "  [!] HTTP Listener: Present (insecure)" -ForegroundColor Red
            $issues += "HTTP listener enabled (should use HTTPS only)"
        } else {
            Write-Host "  [+] HTTP Listener: Not found" -ForegroundColor Green
        }

        # Check listeners
        if ($config.Listeners) {
            Write-Host "`n  Active Listeners:" -ForegroundColor Yellow
            foreach ($listener in $config.Listeners) {
                $transport = ($listener.Keys | Where-Object { $_ -like "Transport=*" }) -replace "Transport=", ""
                $address = ($listener.Keys | Where-Object { $_ -like "Address=*" }) -replace "Address=", ""
                
                if ($transport -eq "HTTP") {
                    Write-Host "    [!] $transport on $address" -ForegroundColor Red
                } else {
                    Write-Host "    [+] $transport on $address" -ForegroundColor Green
                }
            }
        }

        # Check TrustedHosts
        if ($config.TrustedHosts -eq "*") {
            Write-Host "`n  [!] TrustedHosts: * (wildcard - insecure)" -ForegroundColor Red
            $issues += "TrustedHosts set to wildcard (*)"
        } elseif ([string]::IsNullOrEmpty($config.TrustedHosts)) {
            Write-Host "`n  [+] TrustedHosts: Not configured (secure)" -ForegroundColor Green
        } else {
            Write-Host "`n  [+] TrustedHosts: $($config.TrustedHosts)" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    if ($issues.Count -gt 0) {
        Write-Host "[!] VULNERABLE: WinRM security issues detected" -ForegroundColor Red
        foreach ($issue in $issues) {
            Write-Host "    - $issue" -ForegroundColor Red
        }
        Write-Host ""
        return $false
    } elseif ($config.ServiceStatus -eq 'Running') {
        Write-Host "[+] SECURE: WinRM security is properly configured" -ForegroundColor Green
        return $true
    } else {
        Write-Host "[+] INFO: WinRM service is not running" -ForegroundColor Green
        return $true
    }
}
catch {
    Write-Host "[!] ERROR: Failed to check WinRM security configuration" -ForegroundColor Red
    Write-Host "    $_" -ForegroundColor Red
    return $null
}
