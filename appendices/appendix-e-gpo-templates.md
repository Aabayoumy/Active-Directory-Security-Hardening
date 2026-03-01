[← Back to Main](../README.md)

# Appendix E: GPO Baseline Configuration Templates

## Group Policy Object Security Settings Reference

This appendix provides complete GPO configuration templates for all security hardening measures, including export instructions and baseline settings.

---

## Table of Contents

1. [GPO Structure Overview](#gpo-structure-overview)
2. [Domain Controllers Baseline GPO](#domain-controllers-baseline-gpo)
3. [Member Servers Baseline GPO](#member-servers-baseline-gpo)
4. [Workstations Baseline GPO](#workstations-baseline-gpo)
5. [LAPS Configuration GPO](#laps-configuration-gpo)
6. [Advanced Audit Policy GPO](#advanced-audit-policy-gpo)
7. [LDAP Security GPO](#ldap-security-gpo)
8. [Protocol Security GPO](#protocol-security-gpo)
9. [GPO Import/Export Instructions](#gpo-import-export-instructions)

---

## GPO Structure Overview

### Recommended GPO Organization

```
GPO Hierarchy (by priority):
├── Domain Controllers OU
│   ├── [1] DC - Security Baseline (Link Order: 1)
│   ├── [2] DC - Advanced Audit Policy (Link Order: 2)
│   └── [3] DC - Protocol Security (Link Order: 3)
│
├── Member Servers OU
│   ├── [1] Servers - Security Baseline (Link Order: 1)
│   ├── [2] Servers - LAPS Configuration (Link Order: 2)
│   └── [3] Servers - Audit Policy (Link Order: 3)
│
└── Workstations OU
    ├── [1] Workstations - Security Baseline (Link Order: 1)
    ├── [2] Workstations - LAPS Configuration (Link Order: 2)
    └── [3] Workstations - Protocol Security (Link Order: 3)
```

---

## Domain Controllers Baseline GPO

### GPO Name: `DC - Security Baseline`

**Link Location:** `OU=Domain Controllers,DC=contoso,DC=com`

**Enforcement:** Enabled, No Override

---

### Computer Configuration Settings

#### Security Settings → Local Policies → Security Options

```
Policy Setting: Network security: LAN Manager authentication level
Value: Send NTLMv2 response only. Refuse LM & NTLM
Registry: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel = 5

Policy Setting: Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers
Value: Deny all
Registry: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic = 2

Policy Setting: Network security: Restrict NTLM: Add remote server exceptions for NTLM authentication
Value: (Leave blank - no exceptions)

Policy Setting: Accounts: Rename administrator account
Value: ADM-Local-DC (or organization-specific name)

Policy Setting: Accounts: Rename guest account  
Value: GuestDisabled

Policy Setting: Accounts: Guest account status
Value: Disabled

Policy Setting: Interactive logon: Do not display last user name
Value: Enabled

Policy Setting: Interactive logon: Machine inactivity limit
Value: 900 seconds (15 minutes)

Policy Setting: Microsoft network server: Digitally sign communications (always)
Value: Enabled

Policy Setting: Domain controller: LDAP server signing requirements
Value: Require signing
Registry: HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity = 2

Policy Setting: Domain controller: Refuse machine account password changes
Value: Disabled (allow password changes)
```

---

#### System Services

```
Service: Print Spooler
Startup Mode: Disabled
Service Name: Spooler
```

---

#### Windows Firewall → Domain Profile

```
Setting: Firewall state
Value: On (recommended)

Setting: Inbound connections
Value: Block (default)

Setting: Outbound connections
Value: Allow (default)

Setting: Display a notification
Value: No

Setting: Logging - Log dropped packets
Value: Yes
```

---

#### Advanced Audit Policy Configuration → Account Logon

```
Audit Credential Validation: Success and Failure
Audit Kerberos Authentication Service: Success and Failure
Audit Kerberos Service Ticket Operations: Success and Failure
```

---

### PowerShell Script to Apply DC Baseline GPO

```powershell
<#
.SYNOPSIS
    Create and configure Domain Controllers Security Baseline GPO
#>

$gpoName = "DC - Security Baseline"
$targetOU = "OU=Domain Controllers,DC=contoso,DC=com"

# Create GPO
Write-Host "Creating GPO: $gpoName" -ForegroundColor Green
$gpo = New-GPO -Name $gpoName -Comment "Domain Controllers security baseline - NTLM restrictions, service hardening, firewall"

# Link GPO to Domain Controllers OU
New-GPLink -Name $gpoName -Target $targetOU -LinkEnabled Yes -Enforced Yes

Write-Host "[OK] GPO created and linked to $targetOU" -ForegroundColor Green

# Configure security settings using GPO cmdlets
Write-Host "Configuring security settings..." -ForegroundColor Green

# Note: Some settings require manual GPO editor configuration or secedit templates
# The following demonstrates registry-based settings via GPO Preferences

# For complete configuration, use Group Policy Management Console (GPMC.msc)
# Navigate to: Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options

Write-Host "`n[ACTION REQUIRED] Complete configuration in GPMC:"
Write-Host "1. Edit GPO: $gpoName"
Write-Host "2. Configure Security Options as listed in this appendix"
Write-Host "3. Configure Advanced Audit Policy settings"
Write-Host "4. Disable Print Spooler service"
Write-Host "5. Run: gpupdate /force on all Domain Controllers"
```

---

## Member Servers Baseline GPO

### GPO Name: `Servers - Security Baseline`

**Link Location:** `OU=Member Servers,DC=contoso,DC=com`

---

### Computer Configuration Settings

#### Security Settings → Local Policies → Security Options

```
Network security: LAN Manager authentication level
Value: Send NTLMv2 response only. Refuse LM & NTLM

Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers
Value: Audit all (monitor before enforcing)

Accounts: Rename administrator account
Value: ADM-Local-Server

Interactive logon: Machine inactivity limit
Value: 900 seconds (15 minutes)

Interactive logon: Smart card removal behavior
Value: Lock Workstation

Microsoft network server: Digitally sign communications (always)
Value: Enabled

Network access: Do not allow anonymous enumeration of SAM accounts
Value: Enabled

Network access: Do not allow anonymous enumeration of SAM accounts and shares
Value: Enabled
```

---

#### System Services

```
Service: Print Spooler
Startup Mode: Disabled (unless required for print servers)

Service: Remote Registry
Startup Mode: Disabled
```

---

#### Windows Firewall

```
Domain Profile → Firewall state: On
Private Profile → Firewall state: On
Public Profile → Firewall state: On
Public Profile → Inbound connections: Block all
```

---

## Workstations Baseline GPO

### GPO Name: `Workstations - Security Baseline`

**Link Location:** `OU=Workstations,DC=contoso,DC=com`

---

### Computer Configuration Settings

#### Security Settings → Local Policies → Security Options

```
Network security: LAN Manager authentication level
Value: Send NTLMv2 response only. Refuse LM & NTLM

Interactive logon: Do not display last user name
Value: Enabled

Interactive logon: Machine inactivity limit
Value: 600 seconds (10 minutes)

Shutdown: Allow system to be shut down without having to log on
Value: Disabled

User Account Control: Admin Approval Mode for the Built-in Administrator account
Value: Enabled

User Account Control: Behavior of the elevation prompt for administrators
Value: Prompt for consent on the secure desktop
```

---

#### Administrative Templates → Windows Components → Windows Remote Management (WinRM)

```
Computer Configuration → Administrative Templates → Windows Components → Windows Remote Management (WinRM) → WinRM Service

Setting: Allow remote server management through WinRM
Value: Disabled (or configure with specific IP filters)

Setting: Disallow WinRM from storing RunAs credentials
Value: Enabled
```

---

#### Administrative Templates → Network → DNS Client

```
Computer Configuration → Administrative Templates → Network → DNS Client

Setting: Turn off multicast name resolution (LLMNR)
Value: Enabled
```

---

#### Administrative Templates → Network → Lanman Workstation

```
Computer Configuration → Administrative Templates → Network → Lanman Workstation

Setting: Enable insecure guest logons
Value: Disabled
```

---

## LAPS Configuration GPO

### GPO Name: `LAPS - Password Management`

**Link Location:** `OU=Workstations,DC=contoso,DC=com` and `OU=Member Servers,DC=contoso,DC=com`

---

### Computer Configuration Settings

#### Administrative Templates → System → LAPS

```
Setting: Enable Local Admin Password Management
Value: Enabled

Setting: Configure password backup directory
Value: Enabled
  Backup directory: Active Directory

Setting: Password Settings
Value: Enabled
  Password Complexity: 4 (Large letters + small letters + numbers + specials)
  Password Length: 14
  Password Age (Days): 30

Setting: Name of administrator account to manage
Value: Enabled
  Administrator account name: Administrator

Setting: Do not allow password expiration time longer than required
Value: Enabled

Setting: Post-authentication actions
Value: Enabled
  Post-authentication actions: Reset password and logoff managed account
```

---

### PowerShell Script to Create LAPS GPO

```powershell
<#
.SYNOPSIS
    Create Windows LAPS GPO configuration
#>

$gpoName = "LAPS - Password Management"
$workstationsOU = "OU=Workstations,DC=contoso,DC=com"
$serversOU = "OU=Member Servers,DC=contoso,DC=com"

# Create GPO
$gpo = New-GPO -Name $gpoName -Comment "Windows LAPS automatic password management for local administrator accounts"

# Link to OUs
New-GPLink -Name $gpoName -Target $workstationsOU -LinkEnabled Yes
New-GPLink -Name $gpoName -Target $serversOU -LinkEnabled Yes

Write-Host "[OK] LAPS GPO created and linked" -ForegroundColor Green

Write-Host "`n[GPO CONFIGURATION REQUIRED]"
Write-Host "1. Edit GPO in GPMC: $gpoName"
Write-Host "2. Navigate to: Computer Configuration → Administrative Templates → System → LAPS"
Write-Host "3. Enable and configure all LAPS settings as documented above"
Write-Host "4. Run gpupdate /force on target computers"
Write-Host "5. Verify with: Get-ADComputer <name> -Properties ms-Mcs-AdmPwd"
```

---

## Advanced Audit Policy GPO

### GPO Name: `Advanced Audit Policy - Domain Controllers`

**Link Location:** `OU=Domain Controllers,DC=contoso,DC=com`

---

### Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration

#### Account Logon

```
Audit Credential Validation: Success and Failure
Audit Kerberos Authentication Service: Success and Failure
Audit Kerberos Service Ticket Operations: Success and Failure
Audit Other Account Logon Events: Success and Failure
```

#### Account Management

```
Audit Computer Account Management: Success and Failure
Audit Distribution Group Management: Success
Audit Other Account Management Events: Success and Failure
Audit Security Group Management: Success and Failure
Audit User Account Management: Success and Failure
```

#### DS Access (Directory Service Access)

```
Audit Directory Service Access: Failure
Audit Directory Service Changes: Success and Failure
Audit Directory Service Replication: Failure
```

#### Logon/Logoff

```
Audit Account Lockout: Failure
Audit Logoff: Success
Audit Logon: Success and Failure
Audit Other Logon/Logoff Events: Success and Failure
Audit Special Logon: Success and Failure
```

#### Object Access

```
Audit File Share: Failure
Audit File System: Failure
Audit Registry: Failure
Audit SAM: Success and Failure
```

#### Policy Change

```
Audit Audit Policy Change: Success and Failure
Audit Authentication Policy Change: Success and Failure
Audit Authorization Policy Change: Success
Audit MPSSVC Rule-Level Policy Change: Success and Failure
```

#### Privilege Use

```
Audit Sensitive Privilege Use: Success and Failure
```

#### System

```
Audit IPsec Driver: Failure
Audit Security State Change: Success and Failure
Audit Security System Extension: Success and Failure
Audit System Integrity: Success and Failure
```

---

### PowerShell Script to Apply Advanced Audit Policy

```powershell
<#
.SYNOPSIS
    Configure Advanced Audit Policy for Domain Controllers
.DESCRIPTION
    Applies comprehensive audit settings via auditpol
#>

Write-Host "=== Applying Advanced Audit Policy ===" -ForegroundColor Green

# Account Logon
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable

# Account Management
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Distribution Group Management" /success:enable
auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

# Directory Service Access
auditpol /set /subcategory:"Directory Service Access" /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Replication" /failure:enable

# Logon/Logoff
auditpol /set /subcategory:"Account Lockout" /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable

# Object Access
auditpol /set /subcategory:"File Share" /failure:enable
auditpol /set /subcategory:"File System" /failure:enable
auditpol /set /subcategory:"Registry" /failure:enable
auditpol /set /subcategory:"SAM" /success:enable /failure:enable

# Policy Change
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authorization Policy Change" /success:enable
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable

# Privilege Use
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# System
auditpol /set /subcategory:"IPsec Driver" /failure:enable
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

Write-Host "`n[OK] Advanced Audit Policy applied successfully" -ForegroundColor Green

# Export audit policy for backup
$backupPath = "C:\Temp\AuditPolicy_Backup.csv"
auditpol /backup /file:$backupPath
Write-Host "[OK] Audit policy backed up to: $backupPath" -ForegroundColor Green

# Verify configuration
Write-Host "`n=== Verification ===" -ForegroundColor Yellow
Write-Host "Checking sample audit settings..."
auditpol /get /subcategory:"Credential Validation"
auditpol /get /subcategory:"User Account Management"
```

---

## LDAP Security GPO

### GPO Name: `LDAP - Security Hardening`

**Link Location:** `OU=Domain Controllers,DC=contoso,DC=com`

---

### Computer Configuration → Preferences → Windows Settings → Registry

#### LDAP Signing Requirement

```
Action: Update
Hive: HKEY_LOCAL_MACHINE
Key Path: SYSTEM\CurrentControlSet\Services\NTDS\Parameters
Value name: LDAPServerIntegrity
Value type: REG_DWORD
Value data: 2
```

#### LDAPS Channel Binding

```
Action: Update
Hive: HKEY_LOCAL_MACHINE
Key Path: SYSTEM\CurrentControlSet\Services\NTDS\Parameters
Value name: LdapEnforceChannelBinding
Value type: REG_DWORD
Value data: 1
```

---

## Protocol Security GPO

### GPO Name: `Protocol Security - LLMNR and NetBIOS`

**Link Location:** `Domain Root (contoso.com)` - applies to all computers

---

### Computer Configuration Settings

#### Administrative Templates → Network → DNS Client

```
Setting: Turn off multicast name resolution
Value: Enabled
Registry: HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast = 0
```

---

### Computer Configuration → Preferences → Windows Settings → Registry

#### Disable NetBIOS over TCP/IP (via startup script)

Create startup script:

```powershell
# Disable-NetBIOS.ps1
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True"
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2)  # 2 = Disable NetBIOS
}
```

**GPO Configuration:**
- Computer Configuration → Policies → Windows Settings → Scripts → Startup
- Add: `Disable-NetBIOS.ps1`

---

## GPO Import/Export Instructions

### Export GPO to Backup

```powershell
# Export single GPO
$gpoName = "DC - Security Baseline"
$backupPath = "C:\GPO_Backups"

# Create backup directory
New-Item -Path $backupPath -ItemType Directory -Force

# Backup GPO
Backup-GPO -Name $gpoName -Path $backupPath

Write-Host "[OK] GPO backed up to: $backupPath" -ForegroundColor Green
```

### Export All GPOs

```powershell
# Backup all GPOs in domain
$backupPath = "C:\GPO_Backups\All_GPOs"
New-Item -Path $backupPath -ItemType Directory -Force

$allGPOs = Get-GPO -All
foreach ($gpo in $allGPOs) {
    Backup-GPO -Name $gpo.DisplayName -Path $backupPath
    Write-Host "Backed up: $($gpo.DisplayName)"
}

Write-Host "`n[OK] All GPOs backed up to: $backupPath" -ForegroundColor Green
```

### Import GPO from Backup

```powershell
# Import/Restore GPO from backup
$backupPath = "C:\GPO_Backups"
$gpoName = "DC - Security Baseline"

# List available backups
$backups = Get-ChildItem -Path $backupPath -Directory
$backups | ForEach-Object {
    Write-Host "Backup: $($_.Name)"
}

# Import GPO (creates new GPO)
$backup = Get-ChildItem -Path $backupPath -Directory | Select-Object -First 1
Import-GPO -BackupId $backup.Name -Path $backupPath -TargetName "Restored-$gpoName" -CreateIfNeeded

# Or restore to existing GPO
Restore-GPO -Name $gpoName -Path $backupPath

Write-Host "[OK] GPO restored successfully" -ForegroundColor Green
```

### Generate GPO HTML Report

```powershell
# Generate detailed GPO report
$gpoName = "DC - Security Baseline"
$reportPath = "C:\GPO_Reports\$gpoName.html"

Get-GPOReport -Name $gpoName -ReportType HTML -Path $reportPath

Write-Host "[OK] GPO report generated: $reportPath" -ForegroundColor Green

# Generate report for all GPOs
Get-GPOReport -All -ReportType HTML -Path "C:\GPO_Reports\All_GPOs_Report.html"
```

---

## GPO Deployment Checklist

### Pre-Deployment

- [ ] GPO created in Group Policy Management Console
- [ ] GPO settings configured according to baseline
- [ ] GPO linked to correct OU
- [ ] Link order set appropriately (higher priority = lower link order number)
- [ ] GPO enforcement configured (if needed)
- [ ] GPO filtering applied (if needed - security filtering/WMI filters)

### Testing

- [ ] GPO tested in pilot OU (2-3 test systems)
- [ ] Group Policy Results (gpresult /h report.html) reviewed
- [ ] No conflicts with existing GPOs identified
- [ ] Application compatibility verified
- [ ] 48-hour monitoring period completed

### Deployment

- [ ] Change management approval obtained
- [ ] Stakeholders notified
- [ ] GPO linked to production OU
- [ ] gpupdate /force executed on target systems
- [ ] Event logs monitored for errors
- [ ] Helpdesk briefed on potential issues

### Post-Deployment

- [ ] GPO verification script executed
- [ ] User/computer functionality tested
- [ ] GPO report generated and archived
- [ ] Documentation updated
- [ ] Rollback plan documented and tested

---

## GPO Troubleshooting Commands

```powershell
# Force Group Policy update
gpupdate /force

# Generate Group Policy Results report (HTML)
gpresult /h C:\Temp\GPResult.html /f

# Check which GPOs apply to computer
gpresult /r /scope:computer

# Check which GPOs apply to user
gpresult /r /scope:user

# Verbose Group Policy processing log
gpresult /v

# Check GPO replication status
Get-GPO -All | ForEach-Object {
    $gpo = $_
    $dcList = Get-ADDomainController -Filter *
    foreach ($dc in $dcList) {
        try {
            $gpoVersion = (Get-GPO -Name $gpo.DisplayName -Server $dc.HostName).ModificationTime
            Write-Host "$($dc.HostName): $($gpo.DisplayName) - Modified: $gpoVersion"
        } catch {
            Write-Warning "$($dc.HostName): Failed to query $($gpo.DisplayName)"
        }
    }
}

# Test GPO link
Get-GPOReport -Name "DC - Security Baseline" -ReportType XML | Select-String "LinksTo"

# Check for disabled GPO links
Get-GPO -All | ForEach-Object {
    $links = (Get-GPO -Name $_.DisplayName).GetLinks()
    if ($links) {
        foreach ($link in $links) {
            if (-not $link.Enabled) {
                Write-Warning "Disabled link: $($_.DisplayName) -> $($link.Target)"
            }
        }
    }
}
```

---

[← Back to Main](../README.md)

---

## Resources

- Group Policy overview: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/group-policy
- Security baseline GPOs: https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines
