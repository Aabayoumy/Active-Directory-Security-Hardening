[← Back to Main](../README.md)

# Appendix D: PowerShell Script Collection

## Detection, Audit, Mitigation, and Verification Scripts

This appendix contains complete PowerShell scripts organized by security control category, following the **Detection → Audit → Mitigation → Verification → Rollback** pattern.

---

## Table of Contents

1. [Password Policy Scripts](#1-password-policy-scripts)
2. [NTLM Authentication Scripts](#2-ntlm-authentication-scripts)
3. [Print Spooler Remediation Scripts](#3-print-spooler-remediation-scripts)
4. [LAPS Deployment Scripts](#4-laps-deployment-scripts)
5. [LDAP Security Scripts](#5-ldap-security-scripts)
6. [RPC Coercion Mitigation Scripts](#6-rpc-coercion-mitigation-scripts)
7. [Advanced Audit Policy Scripts](#7-advanced-audit-policy-scripts)
8. [ADCS Security Scripts](#8-adcs-security-scripts)
9. [Privileged Account Protection Scripts](#9-privileged-account-protection-scripts)
10. [LLMNR and NetBIOS Scripts](#10-llmnr-and-netbios-scripts)
11. [PowerShell Logging Scripts](#11-powershell-logging-scripts)
12. [AD Recycle Bin Scripts](#12-ad-recycle-bin-scripts)
13. [UNC Hardened Paths Scripts](#13-unc-hardened-paths-scripts)
14. [Comprehensive Testing Script](#14-comprehensive-testing-script)

---

## 1. Password Policy Scripts

### Detection Script

```powershell
<#
.SYNOPSIS
    Detect current password policy settings
.DESCRIPTION
    Retrieves default domain password policy and identifies weak configurations
#>

Write-Host "=== Password Policy Detection ===" -ForegroundColor Green

# Get default domain password policy
$policy = Get-ADDefaultDomainPasswordPolicy

Write-Host "`nCurrent Password Policy Settings:"
Write-Host "  Minimum Password Length: $($policy.MinPasswordLength)" -ForegroundColor $(if($policy.MinPasswordLength -lt 12){"Red"}else{"Green"})
Write-Host "  Password History Count: $($policy.PasswordHistoryCount)" -ForegroundColor $(if($policy.PasswordHistoryCount -lt 24){"Yellow"}else{"Green"})
Write-Host "  Complexity Enabled: $($policy.ComplexityEnabled)" -ForegroundColor $(if($policy.ComplexityEnabled){"Green"}else{"Red"})
Write-Host "  Maximum Password Age: $($policy.MaxPasswordAge.Days) days" -ForegroundColor $(if($policy.MaxPasswordAge.Days -gt 90){"Yellow"}else{"Green"})
Write-Host "  Minimum Password Age: $($policy.MinPasswordAge.Days) days"
Write-Host "  Lockout Threshold: $($policy.LockoutThreshold)" -ForegroundColor $(if($policy.LockoutThreshold -eq 0){"Red"}else{"Green"})

# Check for fine-grained password policies
Write-Host "`nFine-Grained Password Policies:"
$fgpp = Get-ADFineGrainedPasswordPolicy -Filter *
if ($fgpp) {
    $fgpp | Select-Object Name, MinPasswordLength, ComplexityEnabled | Format-Table -AutoSize
} else {
    Write-Host "  No fine-grained password policies configured"
}

# Risk Assessment
Write-Host "`n=== Risk Assessment ===" -ForegroundColor Yellow
if ($policy.MinPasswordLength -lt 8) {
    Write-Host "[CRITICAL] Minimum password length < 8 characters" -ForegroundColor Red
} elseif ($policy.MinPasswordLength -lt 12) {
    Write-Host "[HIGH] Minimum password length < 12 characters" -ForegroundColor Red
}

if (-not $policy.ComplexityEnabled) {
    Write-Host "[CRITICAL] Password complexity not enforced" -ForegroundColor Red
}

if ($policy.LockoutThreshold -eq 0) {
    Write-Host "[MEDIUM] Account lockout not configured (brute force risk)" -ForegroundColor Yellow
}
```

### Audit Script

```powershell
<#
.SYNOPSIS
    Audit user accounts before password policy change
.DESCRIPTION
    Identifies users with weak passwords and notifies them
#>

Write-Host "=== Password Policy Audit ===" -ForegroundColor Green

# Identify users who will be impacted by password length increase
Write-Host "`nPreparing user notification for password policy change..."

# Get all enabled user accounts
$users = Get-ADUser -Filter {Enabled -eq $true} -Properties PasswordLastSet, PasswordNeverExpires, EmailAddress

Write-Host "Total enabled users: $($users.Count)"
Write-Host "Users with PasswordNeverExpires: $(($users | Where-Object {$_.PasswordNeverExpires -eq $true}).Count)" -ForegroundColor Yellow

# Export user list for communication
$users | Select-Object Name, SamAccountName, EmailAddress, PasswordLastSet, PasswordNeverExpires | 
    Export-Csv -Path "C:\Temp\Users_PasswordPolicy_Notification.csv" -NoTypeInformation

Write-Host "`n[ACTION REQUIRED] Notify users 48 hours before policy change"
Write-Host "User list exported to: C:\Temp\Users_PasswordPolicy_Notification.csv"
```

### Mitigation Script

```powershell
<#
.SYNOPSIS
    Strengthen password policy to recommended settings
.DESCRIPTION
    Updates default domain password policy with secure settings
#>

Write-Host "=== Password Policy Mitigation ===" -ForegroundColor Green

$domain = "contoso.com"

# Recommended password policy settings
$newPolicy = @{
    Identity = $domain
    MinPasswordLength = 12
    PasswordHistoryCount = 24
    ComplexityEnabled = $true
    MaxPasswordAge = (New-TimeSpan -Days 90)
    MinPasswordAge = (New-TimeSpan -Days 1)
    LockoutThreshold = 5
    LockoutDuration = (New-TimeSpan -Minutes 30)
    LockoutObservationWindow = (New-TimeSpan -Minutes 30)
}

# Apply password policy
try {
    Set-ADDefaultDomainPasswordPolicy @newPolicy
    Write-Host "[OK] Password policy updated successfully" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to update password policy: $_" -ForegroundColor Red
    exit 1
}

# Display new policy
Write-Host "`nNew Password Policy Settings:"
Get-ADDefaultDomainPasswordPolicy | Format-List MinPasswordLength, PasswordHistoryCount, ComplexityEnabled, MaxPasswordAge, MinPasswordAge, LockoutThreshold
```

### Verification Script

```powershell
<#
.SYNOPSIS
    Verify password policy changes applied correctly
.DESCRIPTION
    Confirms password policy meets security requirements
#>

Write-Host "=== Password Policy Verification ===" -ForegroundColor Green

$policy = Get-ADDefaultDomainPasswordPolicy

$checks = @(
    @{Name="Minimum Password Length (>=12)"; Expected=12; Actual=$policy.MinPasswordLength; Operator="ge"}
    @{Name="Password History Count (>=24)"; Expected=24; Actual=$policy.PasswordHistoryCount; Operator="ge"}
    @{Name="Complexity Enabled"; Expected=$true; Actual=$policy.ComplexityEnabled; Operator="eq"}
    @{Name="Max Password Age (<=90 days)"; Expected=90; Actual=$policy.MaxPasswordAge.Days; Operator="le"}
    @{Name="Lockout Threshold (1-10)"; Expected=5; Actual=$policy.LockoutThreshold; Operator="eq"}
)

$allPassed = $true
foreach ($check in $checks) {
    $result = switch ($check.Operator) {
        "ge" { $check.Actual -ge $check.Expected }
        "le" { $check.Actual -le $check.Expected }
        "eq" { $check.Actual -eq $check.Expected }
    }
    
    if ($result) {
        Write-Host "[PASS] $($check.Name): $($check.Actual)" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $($check.Name): Expected $($check.Expected), Got $($check.Actual)" -ForegroundColor Red
        $allPassed = $false
    }
}

if ($allPassed) {
    Write-Host "`n[SUCCESS] All password policy checks passed" -ForegroundColor Green
} else {
    Write-Host "`n[FAILED] Some password policy checks failed" -ForegroundColor Red
}
```

### Rollback Script

```powershell
<#
.SYNOPSIS
    Rollback password policy to previous settings
.DESCRIPTION
    Restores default Windows Server 2022 password policy
#>

Write-Host "=== Password Policy Rollback ===" -ForegroundColor Yellow

Set-ADDefaultDomainPasswordPolicy -Identity "contoso.com" `
    -MinPasswordLength 7 `
    -PasswordHistoryCount 24 `
    -ComplexityEnabled $true `
    -MaxPasswordAge (New-TimeSpan -Days 42) `
    -MinPasswordAge (New-TimeSpan -Days 1)

Write-Host "[OK] Password policy rolled back to defaults" -ForegroundColor Yellow
Get-ADDefaultDomainPasswordPolicy | Format-List MinPasswordLength, ComplexityEnabled
```

---

## 2. NTLM Authentication Scripts

### Detection Script

```powershell
<#
.SYNOPSIS
    Detect NTLM authentication configuration
.DESCRIPTION
    Checks LM authentication level and NTLM audit settings
#>

Write-Host "=== NTLM Authentication Detection ===" -ForegroundColor Green

# Check LM Authentication Level
$lmLevel = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue

if ($lmLevel) {
    Write-Host "`nCurrent LM Authentication Level: $($lmLevel.LmCompatibilityLevel)"
    switch ($lmLevel.LmCompatibilityLevel) {
        0 { Write-Host "  Send LM & NTLM responses" -ForegroundColor Red }
        1 { Write-Host "  Send LM & NTLM - use NTLMv2 session security if negotiated" -ForegroundColor Red }
        2 { Write-Host "  Send NTLM response only" -ForegroundColor Red }
        3 { Write-Host "  Send NTLMv2 response only" -ForegroundColor Yellow }
        4 { Write-Host "  Send NTLMv2 response only. Refuse LM" -ForegroundColor Yellow }
        5 { Write-Host "  Send NTLMv2 response only. Refuse LM & NTLM" -ForegroundColor Green }
    }
} else {
    Write-Host "`n[WARNING] LmCompatibilityLevel not configured (default = 3)" -ForegroundColor Yellow
    Write-Host "  Default allows NTLMv1 authentication"
}

# Check NTLM auditing status
$auditNTLM = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AuditReceivingNTLMTraffic" -ErrorAction SilentlyContinue
Write-Host "`nNTLM Audit Status: $(if($auditNTLM){"Enabled (Value: $($auditNTLM.AuditReceivingNTLMTraffic))"}else{"Disabled"})"

# Check NTLM outbound restrictions
$outbound = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -ErrorAction SilentlyContinue
Write-Host "NTLM Outbound Restrictions: $(if($outbound){"Value: $($outbound.RestrictSendingNTLMTraffic)"}else{"None"})"

Write-Host "`n=== Risk Assessment ===" -ForegroundColor Yellow
if (-not $lmLevel -or $lmLevel.LmCompatibilityLevel -lt 5) {
    Write-Host "[HIGH RISK] NTLMv1/LM authentication is allowed" -ForegroundColor Red
}
```

### Audit Script

```powershell
<#
.SYNOPSIS
    Enable NTLM auditing to identify usage
.DESCRIPTION
    Enables NTLM audit logging for 48-72 hours before enforcement
.NOTES
    Run on all domain controllers
#>

Write-Host "=== NTLM Audit Mode Enablement ===" -ForegroundColor Green

# Enable NTLM incoming traffic auditing
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
    -Name "AuditReceivingNTLMTraffic" -Value 2 -PropertyType DWord -Force | Out-Null

Write-Host "[OK] NTLM auditing enabled (Value: 2 = Audit all NTLM traffic)"

# Enable NTLM outbound auditing (for DCs)
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
    -Name "RestrictSendingNTLMTraffic" -Value 1 -PropertyType DWord -Force | Out-Null

Write-Host "[OK] NTLM outbound auditing enabled (Value: 1 = Audit mode)"

Write-Host "`n=== Monitoring Instructions ===" -ForegroundColor Yellow
Write-Host "1. Monitor Event Viewer for 48-72 hours"
Write-Host "2. Review Security log for Event ID 4624 (Logon events)"
Write-Host "3. Identify systems using NTLM authentication"
Write-Host "4. Run the following command to check NTLM usage:"
Write-Host ""
Write-Host "Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 1000 | " -ForegroundColor Cyan
Write-Host "    Where-Object {`$_.Message -like '*NTLM*'} | " -ForegroundColor Cyan
Write-Host "    Select-Object TimeCreated,Message" -ForegroundColor Cyan
```

### Mitigation Script

```powershell
<#
.SYNOPSIS
    Ban NTLMv1/LM authentication domain-wide
.DESCRIPTION
    Sets LM authentication level to 5 (NTLMv2 only, refuse LM & NTLM)
.NOTES
    Test in pilot OU first. Ensure audit period completed.
#>

Write-Host "=== NTLM Ban Mitigation ===" -ForegroundColor Green

# Set LM Authentication Level to 5
Write-Host "Setting LM Authentication Level to 5..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LmCompatibilityLevel" -Value 5 -Type DWord

Write-Host "[OK] LmCompatibilityLevel set to 5 (NTLMv2 only, refuse LM & NTLM)" -ForegroundColor Green

# Disable NTLM outbound traffic from DCs (RPC coercion mitigation)
Write-Host "`nBlocking NTLM outbound traffic from Domain Controllers..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
    -Name "RestrictSendingNTLMTraffic" -Value 2 -Type DWord

Write-Host "[OK] NTLM outbound traffic blocked (Value: 2)" -ForegroundColor Green

Write-Host "`n=== Post-Mitigation Actions ===" -ForegroundColor Yellow
Write-Host "1. Monitor authentication logs for failures"
Write-Host "2. Check helpdesk tickets for logon issues"
Write-Host "3. Run verification script after 24 hours"
Write-Host "4. Keep rollback script ready for 48 hours"
```

### Verification Script

```powershell
<#
.SYNOPSIS
    Verify NTLM ban is enforced
.DESCRIPTION
    Confirms LM authentication level is set to 5
#>

Write-Host "=== NTLM Ban Verification ===" -ForegroundColor Green

$lmLevel = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel"

if ($lmLevel.LmCompatibilityLevel -eq 5) {
    Write-Host "[PASS] LmCompatibilityLevel = 5 (NTLMv2 only)" -ForegroundColor Green
} else {
    Write-Host "[FAIL] LmCompatibilityLevel = $($lmLevel.LmCompatibilityLevel) (Expected: 5)" -ForegroundColor Red
}

# Check NTLM outbound restrictions on DCs
$computerRole = (Get-WmiObject Win32_ComputerSystem).DomainRole
if ($computerRole -ge 4) {  # 4 = Backup DC, 5 = Primary DC
    $outbound = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic"
    if ($outbound.RestrictSendingNTLMTraffic -eq 2) {
        Write-Host "[PASS] NTLM outbound traffic blocked on DC" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] NTLM outbound traffic not blocked (Value: $($outbound.RestrictSendingNTLMTraffic))" -ForegroundColor Red
    }
}

# Check for failed NTLM authentications
Write-Host "`nChecking for failed NTLM authentications in last 24 hours..."
$failures = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 100 -ErrorAction SilentlyContinue
if ($failures) {
    Write-Host "[WARNING] $($failures.Count) failed authentication events found" -ForegroundColor Yellow
    Write-Host "Review with: Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625;StartTime=(Get-Date).AddHours(-24)}"
} else {
    Write-Host "[OK] No recent failed authentications detected" -ForegroundColor Green
}
```

### Rollback Script

```powershell
<#
.SYNOPSIS
    Rollback NTLM ban to allow NTLMv2
.DESCRIPTION
    Sets LM authentication level to 3 (allows NTLMv2, refuses LM only)
#>

Write-Host "=== NTLM Ban Rollback ===" -ForegroundColor Yellow

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LmCompatibilityLevel" -Value 3

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
    -Name "RestrictSendingNTLMTraffic" -Value 0

Write-Host "[OK] NTLM settings rolled back (LmCompatibilityLevel = 3)" -ForegroundColor Yellow
```

---

## 3. Print Spooler Remediation Scripts

### Detection Script

```powershell
<#
.SYNOPSIS
    Detect Print Spooler service status on domain controllers
.DESCRIPTION
    Checks if Print Spooler is running on DCs (security risk)
#>

Write-Host "=== Print Spooler Detection ===" -ForegroundColor Green

# Get all domain controllers
$domainControllers = (Get-ADDomainController -Filter *).HostName

$results = @()
foreach ($dc in $domainControllers) {
    Write-Host "`nChecking $dc..."
    try {
        $service = Get-Service -Name Spooler -ComputerName $dc -ErrorAction Stop
        $results += [PSCustomObject]@{
            DomainController = $dc
            Status = $service.Status
            StartType = $service.StartType
            Risk = if($service.Status -eq "Running"){"HIGH"}else{"LOW"}
        }
    } catch {
        Write-Warning "Failed to query $dc : $_"
    }
}

$results | Format-Table -AutoSize

$running = $results | Where-Object {$_.Status -eq "Running"}
if ($running) {
    Write-Host "`n[HIGH RISK] Print Spooler running on $($running.Count) DC(s)" -ForegroundColor Red
} else {
    Write-Host "`n[OK] Print Spooler not running on any DC" -ForegroundColor Green
}
```

### Audit Script

```powershell
<#
.SYNOPSIS
    Audit Print Spooler usage on domain controllers
.DESCRIPTION
    Checks if any printers or print jobs exist on DCs
#>

Write-Host "=== Print Spooler Audit ===" -ForegroundColor Green

$domainControllers = (Get-ADDomainController -Filter *).HostName

foreach ($dc in $domainControllers) {
    Write-Host "`n=== $dc ===" -ForegroundColor Cyan
    
    # Check for installed printers
    $printers = Get-Printer -ComputerName $dc -ErrorAction SilentlyContinue
    if ($printers) {
        Write-Host "  Printers installed: $($printers.Count)" -ForegroundColor Yellow
        $printers | Select-Object Name, DriverName | Format-Table
    } else {
        Write-Host "  No printers installed" -ForegroundColor Green
    }
    
    # Check for print jobs
    $printJobs = Get-PrintJob -ComputerName $dc -ErrorAction SilentlyContinue
    if ($printJobs) {
        Write-Host "  Active print jobs: $($printJobs.Count)" -ForegroundColor Yellow
    } else {
        Write-Host "  No print jobs" -ForegroundColor Green
    }
}

Write-Host "`n[AUDIT RESULT] DCs should NOT have printers or print jobs"
Write-Host "If printers exist, investigate business justification before disabling"
```

### Mitigation Script

```powershell
<#
.SYNOPSIS
    Disable Print Spooler service on domain controllers
.DESCRIPTION
    Stops and disables Print Spooler on all DCs
.NOTES
    CVE-2021-34527 (PrintNightmare) mitigation
#>

Write-Host "=== Print Spooler Mitigation ===" -ForegroundColor Green

$domainControllers = (Get-ADDomainController -Filter *).HostName

foreach ($dc in $domainControllers) {
    Write-Host "`nDisabling Print Spooler on $dc..."
    try {
        Invoke-Command -ComputerName $dc -ScriptBlock {
            # Stop service
            Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
            
            # Disable service
            Set-Service -Name Spooler -StartupType Disabled
            
            Write-Host "  [OK] Print Spooler disabled on $env:COMPUTERNAME" -ForegroundColor Green
        }
    } catch {
        Write-Warning "  [ERROR] Failed to disable Print Spooler on $dc : $_"
    }
}

Write-Host "`n[SUCCESS] Print Spooler mitigation completed" -ForegroundColor Green
```

### Verification Script

```powershell
<#
.SYNOPSIS
    Verify Print Spooler is disabled on all domain controllers
.DESCRIPTION
    Confirms Print Spooler service is stopped and disabled
#>

Write-Host "=== Print Spooler Verification ===" -ForegroundColor Green

$domainControllers = (Get-ADDomainController -Filter *).HostName

$allPassed = $true
foreach ($dc in $domainControllers) {
    $service = Get-Service -Name Spooler -ComputerName $dc
    
    if ($service.Status -eq "Stopped" -and $service.StartType -eq "Disabled") {
        Write-Host "[PASS] $dc - Print Spooler is stopped and disabled" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $dc - Status: $($service.Status), StartType: $($service.StartType)" -ForegroundColor Red
        $allPassed = $false
    }
}

if ($allPassed) {
    Write-Host "`n[SUCCESS] All domain controllers verified" -ForegroundColor Green
} else {
    Write-Host "`n[FAILED] Some domain controllers require remediation" -ForegroundColor Red
}
```

### Rollback Script

```powershell
<#
.SYNOPSIS
    Rollback - Re-enable Print Spooler service
.DESCRIPTION
    Sets Print Spooler to Manual startup (does not start service)
#>

Write-Host "=== Print Spooler Rollback ===" -ForegroundColor Yellow

$domainControllers = (Get-ADDomainController -Filter *).HostName

foreach ($dc in $domainControllers) {
    Invoke-Command -ComputerName $dc -ScriptBlock {
        Set-Service -Name Spooler -StartupType Manual
    }
    Write-Host "[OK] $dc - Print Spooler set to Manual" -ForegroundColor Yellow
}
```

---

## 4. LAPS Deployment Scripts

### Detection Script

```powershell
<#
.SYNOPSIS
    Detect Windows LAPS deployment status
.DESCRIPTION
    Checks if Windows LAPS is configured in domain
.NOTES
    Windows Server 2022 includes native Windows LAPS (built-in)
#>

Write-Host "=== Windows LAPS Detection ===" -ForegroundColor Green

# Check if AD schema has LAPS attributes
Write-Host "`nChecking AD Schema for LAPS attributes..."
$lapsPassword = Get-ADObject "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,DC=contoso,DC=com" -ErrorAction SilentlyContinue
$lapsExpiration = Get-ADObject "CN=ms-Mcs-AdmPwdExpirationTime,CN=Schema,CN=Configuration,DC=contoso,DC=com" -ErrorAction SilentlyContinue

if ($lapsPassword -and $lapsExpiration) {
    Write-Host "  [OK] LAPS schema attributes exist" -ForegroundColor Green
} else {
    Write-Host "  [WARNING] LAPS schema attributes not found" -ForegroundColor Yellow
}

# Check if any computers have LAPS passwords set
Write-Host "`nChecking for computers with LAPS passwords..."
$computersWithLAPS = Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | 
    Where-Object {$_.'ms-Mcs-AdmPwd' -ne $null}

Write-Host "  Computers with LAPS passwords: $($computersWithLAPS.Count)"

if ($computersWithLAPS) {
    $computersWithLAPS | Select-Object Name, -Property @{N='PasswordExpiry';E={
        [datetime]::FromFileTime($_.'ms-Mcs-AdmPwdExpirationTime')
    }} | Format-Table -AutoSize
} else {
    Write-Host "  [WARNING] No computers managed by LAPS" -ForegroundColor Yellow
}

# Check LAPS GPO settings
Write-Host "`nChecking for LAPS Group Policy settings..."
$lapsGPO = Get-GPO -All | Where-Object {$_.DisplayName -like "*LAPS*"}
if ($lapsGPO) {
    Write-Host "  LAPS GPOs found: $($lapsGPO.Count)"
    $lapsGPO | Select-Object DisplayName, GpoStatus | Format-Table -AutoSize
} else {
    Write-Host "  [WARNING] No LAPS GPOs found" -ForegroundColor Yellow
}
```

### Audit Script (Pilot Deployment)

```powershell
<#
.SYNOPSIS
    Audit script for LAPS pilot deployment
.DESCRIPTION
    Creates pilot OU and prepares test computers
#>

Write-Host "=== LAPS Pilot Deployment Audit ===" -ForegroundColor Green

# Create pilot OU
$ouPath = "DC=contoso,DC=com"
$pilotOUName = "LAPS-Pilot"

Write-Host "`nCreating pilot OU..."
try {
    New-ADOrganizationalUnit -Name $pilotOUName -Path $ouPath -ProtectedFromAccidentalDeletion $false
    Write-Host "  [OK] OU created: $pilotOUName" -ForegroundColor Green
} catch {
    Write-Host "  [INFO] OU already exists or error: $_" -ForegroundColor Yellow
}

# Identify candidate computers for pilot
Write-Host "`nIdentifying candidate workstations for pilot..."
$workstations = Get-ADComputer -Filter {OperatingSystem -like "*Windows 11*" -or OperatingSystem -like "*Windows 10*"} -SearchBase $ouPath |
    Select-Object -First 3

Write-Host "  Pilot candidates: $($workstations.Count)"
$workstations | Select-Object Name, OperatingSystem | Format-Table -AutoSize

Write-Host "`n[ACTION REQUIRED] Move pilot computers to OU:"
foreach ($ws in $workstations) {
    Write-Host "  Move-ADObject -Identity '$($ws.DistinguishedName)' -TargetPath 'OU=$pilotOUName,$ouPath'"
}
```

### Mitigation Script (LAPS Deployment)

```powershell
<#
.SYNOPSIS
    Deploy Windows LAPS via Group Policy
.DESCRIPTION
    Creates and configures LAPS GPO for domain-wide deployment
.NOTES
    Windows Server 2022 / Windows 11 native LAPS
#>

Write-Host "=== Windows LAPS Deployment ===" -ForegroundColor Green

# LAPS Configuration
$gpoName = "Windows LAPS Policy"
$targetOU = "OU=Workstations,DC=contoso,DC=com"

# Create GPO
Write-Host "`nCreating LAPS Group Policy..."
try {
    $gpo = New-GPO -Name $gpoName -Comment "Windows LAPS password management"
    Write-Host "  [OK] GPO created: $gpoName" -ForegroundColor Green
} catch {
    Write-Host "  [INFO] GPO may already exist" -ForegroundColor Yellow
    $gpo = Get-GPO -Name $gpoName
}

# Link GPO to target OU
Write-Host "Linking GPO to OU..."
New-GPLink -Name $gpoName -Target $targetOU -LinkEnabled Yes -ErrorAction SilentlyContinue

# Configure LAPS settings via registry (GPO preferences)
Write-Host "Configuring LAPS settings..."

# Note: Windows LAPS settings are configured via:
# Computer Configuration → Administrative Templates → System → LAPS

# Via PowerShell (example registry values for reference)
$lapsRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"

$lapsSettings = @{
    "BackupDirectory" = 2  # 1 = Azure AD, 2 = Active Directory, 3 = Both
    "PasswordComplexity" = 4  # 4 = Large, small, numbers, specials
    "PasswordLength" = 14
    "PasswordAgeDays" = 30
    "AdministratorAccountName" = "Administrator"
}

Write-Host "`nRecommended LAPS Settings:"
$lapsSettings.GetEnumerator() | ForEach-Object {
    Write-Host "  $($_.Key): $($_.Value)"
}

Write-Host "`n[GPO CONFIGURATION REQUIRED]"
Write-Host "1. Open Group Policy Management"
Write-Host "2. Edit GPO: $gpoName"
Write-Host "3. Navigate to: Computer Configuration → Administrative Templates → System → LAPS"
Write-Host "4. Configure:"
Write-Host "   - Enable 'Configure password backup directory' (Value: Active Directory)"
Write-Host "   - Configure 'Password Settings' (Complexity: 4, Length: 14, Age: 30 days)"
Write-Host "   - Enable 'Name of administrator account to manage' (Value: Administrator)"

Write-Host "`n5. Run on target computers: gpupdate /force"
```

### Verification Script

```powershell
<#
.SYNOPSIS
    Verify Windows LAPS deployment
.DESCRIPTION
    Checks if LAPS passwords are being managed in AD
#>

Write-Host "=== Windows LAPS Verification ===" -ForegroundColor Green

# Check computers with LAPS passwords
$computersWithLAPS = Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime | 
    Where-Object {$_.'ms-Mcs-AdmPwd' -ne $null}

Write-Host "`nComputers managed by LAPS: $($computersWithLAPS.Count)"

if ($computersWithLAPS.Count -gt 0) {
    Write-Host "[PASS] LAPS is actively managing passwords" -ForegroundColor Green
    
    # Display sample (without revealing passwords)
    $computersWithLAPS | Select-Object Name, @{
        N='PasswordExpiry'
        E={[datetime]::FromFileTime($_.'ms-Mcs-AdmPwdExpirationTime')}
    } | Format-Table -AutoSize | Select-Object -First 10
} else {
    Write-Host "[FAIL] No computers have LAPS passwords" -ForegroundColor Red
    Write-Host "Check:"
    Write-Host "  1. GPO is linked to OU containing computers"
    Write-Host "  2. Computers have rebooted and run gpupdate /force"
    Write-Host "  3. Computers have write permission on their own ms-Mcs-AdmPwd attribute"
}

# Verify LAPS password can be retrieved (requires delegated permissions)
Write-Host "`nTesting LAPS password retrieval (first computer)..."
if ($computersWithLAPS.Count -gt 0) {
    $testComputer = $computersWithLAPS[0]
    try {
        $password = Get-ADComputer -Identity $testComputer.Name -Properties ms-Mcs-AdmPwd | 
            Select-Object -ExpandProperty ms-Mcs-AdmPwd
        if ($password) {
            Write-Host "[PASS] LAPS password retrieved successfully (length: $($password.Length) characters)" -ForegroundColor Green
        }
    } catch {
        Write-Host "[WARNING] Unable to retrieve password: $_" -ForegroundColor Yellow
    }
}
```

---

## 5. LDAP Security Scripts

### LDAP Signing Detection Script

```powershell
<#
.SYNOPSIS
    Detect LDAP signing configuration
.DESCRIPTION
    Checks if LDAP signing is required on domain controllers
#>

Write-Host "=== LDAP Signing Detection ===" -ForegroundColor Green

$ldapSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue

if ($ldapSigning) {
    Write-Host "LDAP Server Integrity: $($ldapSigning.LDAPServerIntegrity)"
    switch ($ldapSigning.LDAPServerIntegrity) {
        0 { Write-Host "  No signing required (INSECURE)" -ForegroundColor Red }
        1 { Write-Host "  Signing negotiated" -ForegroundColor Yellow }
        2 { Write-Host "  Signing required (SECURE)" -ForegroundColor Green }
    }
} else {
    Write-Host "[WARNING] LDAPServerIntegrity not configured (default: no signing)" -ForegroundColor Red
}
```

### LDAP Signing Audit Script

```powershell
<#
.SYNOPSIS
    Enable LDAP diagnostics to identify unsigned binds
.DESCRIPTION
    Enables LDAP logging to monitor for unsigned connections
#>

Write-Host "=== LDAP Signing Audit Mode ===" -ForegroundColor Green

# Enable LDAP diagnostics (Event ID 2889)
Write-Host "Enabling LDAP Interface Events diagnostics..."
reg add "HKLM\System\CurrentControlSet\Services\NTDS\Diagnostics" `
    /v "16 LDAP Interface Events" /t REG_DWORD /d 2 /f | Out-Null

Write-Host "[OK] LDAP diagnostics enabled" -ForegroundColor Green

Write-Host "`n=== Monitoring Instructions ===" -ForegroundColor Yellow
Write-Host "1. Monitor Directory Service event log for 48-72 hours"
Write-Host "2. Check for Event ID 2889 (unsigned LDAP binds)"
Write-Host "3. Run the following command to review unsigned binds:"
Write-Host ""
Write-Host "Get-WinEvent -FilterHashtable @{LogName='Directory Service';ID=2889} | " -ForegroundColor Cyan
Write-Host "    Select-Object TimeCreated,Message | Format-List" -ForegroundColor Cyan
Write-Host ""
Write-Host "4. Contact application owners before enforcing LDAP signing"
```

### LDAP Signing Mitigation Script

```powershell
<#
.SYNOPSIS
    Require LDAP signing on domain controllers
.DESCRIPTION
    Sets LDAPServerIntegrity to 2 (require signing)
#>

Write-Host "=== LDAP Signing Mitigation ===" -ForegroundColor Green

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LDAPServerIntegrity" -Value 2

Write-Host "[OK] LDAP signing required (LDAPServerIntegrity = 2)" -ForegroundColor Green

Write-Host "`n[ACTION REQUIRED] Restart is NOT required, but monitor for 24-48 hours"
Write-Host "Check for authentication failures in Directory Service log"
```

### LDAPS Channel Binding Scripts

```powershell
<#
.SYNOPSIS
    Configure LDAPS channel binding
.DESCRIPTION
    Enables LDAPS channel binding for enhanced security
#>

Write-Host "=== LDAPS Channel Binding Configuration ===" -ForegroundColor Green

# Detection
Write-Host "`nDetecting current channel binding status..."
$channelBinding = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue

if ($channelBinding) {
    Write-Host "Current setting: $($channelBinding.LdapEnforceChannelBinding)"
    switch ($channelBinding.LdapEnforceChannelBinding) {
        0 { Write-Host "  Never enforce (default)" -ForegroundColor Yellow }
        1 { Write-Host "  Enforce when supported" -ForegroundColor Yellow }
        2 { Write-Host "  Always enforce" -ForegroundColor Green }
    }
} else {
    Write-Host "  Not configured (default: 0)" -ForegroundColor Yellow
}

# Mitigation
Write-Host "`nEnabling LDAPS channel binding..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LdapEnforceChannelBinding" -Value 1  # 1 = when supported

Write-Host "[OK] LDAPS channel binding enabled (Value: 1)" -ForegroundColor Green

# Verification
$verify = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LdapEnforceChannelBinding"

if ($verify.LdapEnforceChannelBinding -eq 1) {
    Write-Host "[PASS] Channel binding verified" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Channel binding not set correctly" -ForegroundColor Red
}
```

---

## 14. Comprehensive Testing Script

### All-in-One Security Configuration Verification

```powershell
<#
.SYNOPSIS
    Comprehensive Active Directory security configuration tester
.DESCRIPTION
    Tests all security hardening configurations and generates report
.OUTPUTS
    HTML report: C:\Temp\AD_Security_Report.html
#>

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  AD Security Configuration Tester  " -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

$results = @()

# Test 1: Password Policy
Write-Host "`n[1/12] Testing Password Policy..." -ForegroundColor Green
$pwdPolicy = Get-ADDefaultDomainPasswordPolicy
$results += [PSCustomObject]@{
    Category = "Password Policy"
    Check = "Minimum Password Length >= 12"
    Status = if($pwdPolicy.MinPasswordLength -ge 12){"PASS"}else{"FAIL"}
    Value = $pwdPolicy.MinPasswordLength
}

# Test 2: NTLM Authentication
Write-Host "[2/12] Testing NTLM Configuration..." -ForegroundColor Green
$lmLevel = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
$results += [PSCustomObject]@{
    Category = "NTLM"
    Check = "LM Authentication Level = 5"
    Status = if($lmLevel.LmCompatibilityLevel -eq 5){"PASS"}else{"FAIL"}
    Value = $lmLevel.LmCompatibilityLevel
}

# Test 3: Print Spooler
Write-Host "[3/12] Testing Print Spooler Status..." -ForegroundColor Green
$spooler = Get-Service -Name Spooler
$results += [PSCustomObject]@{
    Category = "Print Spooler"
    Check = "Service Disabled on DC"
    Status = if($spooler.StartType -eq "Disabled"){"PASS"}else{"FAIL"}
    Value = "$($spooler.Status) / $($spooler.StartType)"
}

# Test 4: LAPS Deployment
Write-Host "[4/12] Testing LAPS Deployment..." -ForegroundColor Green
$lapsComputers = (Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Where-Object {$_.'ms-Mcs-AdmPwd' -ne $null}).Count
$results += [PSCustomObject]@{
    Category = "LAPS"
    Check = "Computers with LAPS passwords"
    Status = if($lapsComputers -gt 0){"PASS"}else{"FAIL"}
    Value = $lapsComputers
}

# Test 5: LDAP Signing
Write-Host "[5/12] Testing LDAP Signing..." -ForegroundColor Green
$ldapSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
$results += [PSCustomObject]@{
    Category = "LDAP"
    Check = "LDAP Signing Required"
    Status = if($ldapSigning.LDAPServerIntegrity -eq 2){"PASS"}else{"FAIL"}
    Value = $ldapSigning.LDAPServerIntegrity
}

# Test 6: LDAPS Channel Binding
Write-Host "[6/12] Testing LDAPS Channel Binding..." -ForegroundColor Green
$channelBinding = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue
$results += [PSCustomObject]@{
    Category = "LDAPS"
    Check = "Channel Binding Enabled"
    Status = if($channelBinding.LdapEnforceChannelBinding -ge 1){"PASS"}else{"FAIL"}
    Value = $channelBinding.LdapEnforceChannelBinding
}

# Test 7: Schema Admins Group
Write-Host "[7/12] Testing Schema Admins Group..." -ForegroundColor Green
$schemaAdmins = (Get-ADGroupMember "Schema Admins" -ErrorAction SilentlyContinue).Count
$results += [PSCustomObject]@{
    Category = "Privileged Groups"
    Check = "Schema Admins Empty"
    Status = if($schemaAdmins -eq 0){"PASS"}else{"FAIL"}
    Value = "$schemaAdmins members"
}

# Test 8: AD Recycle Bin
Write-Host "[8/12] Testing AD Recycle Bin..." -ForegroundColor Green
$recycleBin = (Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"').EnabledScopes
$results += [PSCustomObject]@{
    Category = "AD Features"
    Check = "AD Recycle Bin Enabled"
    Status = if($recycleBin){"PASS"}else{"FAIL"}
    Value = if($recycleBin){"Enabled"}else{"Disabled"}
}

# Test 9: LLMNR
Write-Host "[9/12] Testing LLMNR Configuration..." -ForegroundColor Green
$llmnr = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
$results += [PSCustomObject]@{
    Category = "Name Resolution"
    Check = "LLMNR Disabled"
    Status = if($llmnr.EnableMulticast -eq 0){"PASS"}else{"FAIL"}
    Value = $llmnr.EnableMulticast
}

# Test 10: PowerShell Logging
Write-Host "[10/12] Testing PowerShell Logging..." -ForegroundColor Green
$psLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
$results += [PSCustomObject]@{
    Category = "Logging"
    Check = "PowerShell Script Block Logging"
    Status = if($psLogging.EnableScriptBlockLogging -eq 1){"PASS"}else{"FAIL"}
    Value = $psLogging.EnableScriptBlockLogging
}

# Test 11: UNC Hardened Paths
Write-Host "[11/12] Testing UNC Hardened Paths..." -ForegroundColor Green
$uncPaths = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -ErrorAction SilentlyContinue
$results += [PSCustomObject]@{
    Category = "SMB Security"
    Check = "UNC Hardened Paths Configured"
    Status = if($uncPaths){"PASS"}else{"FAIL"}
    Value = if($uncPaths){"Configured"}else{"Not Configured"}
}

# Test 12: Audit Policy
Write-Host "[12/12] Testing Audit Policy..." -ForegroundColor Green
$auditPolicy = auditpol /get /subcategory:"Credential Validation" | Select-String "Success and Failure"
$results += [PSCustomObject]@{
    Category = "Auditing"
    Check = "Advanced Audit Policy"
    Status = if($auditPolicy){"PASS"}else{"FAIL"}
    Value = if($auditPolicy){"Enabled"}else{"Not Configured"}
}

# Display Results
Write-Host "`n====================================" -ForegroundColor Cyan
Write-Host "        Test Results Summary        " -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan

$results | Format-Table Category, Check, Status, Value -AutoSize

# Summary Statistics
$total = $results.Count
$passed = ($results | Where-Object {$_.Status -eq "PASS"}).Count
$failed = ($results | Where-Object {$_.Status -eq "FAIL"}).Count
$passRate = [math]::Round(($passed / $total) * 100, 2)

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Total Tests: $total"
Write-Host "Passed: $passed" -ForegroundColor Green
Write-Host "Failed: $failed" -ForegroundColor $(if($failed -gt 0){"Red"}else{"Green"})
Write-Host "Pass Rate: $passRate%" -ForegroundColor $(if($passRate -ge 80){"Green"}elseif($passRate -ge 60){"Yellow"}else{"Red"})

# Export Results
$reportPath = "C:\Temp\AD_Security_Report.csv"
$results | Export-Csv -Path $reportPath -NoTypeInformation
Write-Host "`nDetailed report exported to: $reportPath" -ForegroundColor Green

# Generate HTML Report
$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>AD Security Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #0066cc; }
        table { border-collapse: collapse; width: 100%; }
        th { background-color: #0066cc; color: white; padding: 10px; text-align: left; }
        td { border: 1px solid #ddd; padding: 8px; }
        .pass { background-color: #d4edda; color: #155724; }
        .fail { background-color: #f8d7da; color: #721c24; }
        .summary { margin-top: 20px; padding: 15px; background-color: #f0f0f0; }
    </style>
</head>
<body>
    <h1>Active Directory Security Assessment Report</h1>
    <p><strong>Generated:</strong> $(Get-Date)</p>
    <p><strong>Domain Controller:</strong> $env:COMPUTERNAME</p>
    
    <table>
        <tr>
            <th>Category</th>
            <th>Check</th>
            <th>Status</th>
            <th>Value</th>
        </tr>
"@

foreach ($result in $results) {
    $statusClass = if($result.Status -eq "PASS"){"pass"}else{"fail"}
    $htmlReport += @"
        <tr class="$statusClass">
            <td>$($result.Category)</td>
            <td>$($result.Check)</td>
            <td>$($result.Status)</td>
            <td>$($result.Value)</td>
        </tr>
"@
}

$htmlReport += @"
    </table>
    
    <div class="summary">
        <h2>Summary Statistics</h2>
        <p><strong>Total Tests:</strong> $total</p>
        <p><strong>Passed:</strong> <span style="color: green;">$passed</span></p>
        <p><strong>Failed:</strong> <span style="color: red;">$failed</span></p>
        <p><strong>Pass Rate:</strong> $passRate%</p>
    </div>
</body>
</html>
"@

$htmlPath = "C:\Temp\AD_Security_Report.html"
$htmlReport | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Host "HTML report exported to: $htmlPath" -ForegroundColor Green

Write-Host "`n[COMPLETE] Security configuration testing finished" -ForegroundColor Green
```

---

[← Back to Main](../README.md)

---

## Resources

- PowerShell documentation: https://learn.microsoft.com/en-us/powershell/
- PowerShell logging and transcription: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging
