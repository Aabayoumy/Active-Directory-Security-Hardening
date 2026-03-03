# Chapter 6: Configuration Hardening and Security Enhancements

[← Previous: Mitigating Insecure Protocols and Authentication](05-protocol-remediation.md) | [Next: Additional Hardening Actions →](07-additional-hardening-actions.md)

---

## Chapter Overview

This chapter addresses security hardening through configuration changes, security feature deployment, and best practice implementations. Building on the protocol remediations in Chapter 5, this chapter focuses on system configuration, privileged access management, audit policies, and directory resilience.

**All remediations follow the standardized workflow:**
- Detection → Audit → Impact Assessment → Mitigation → Verification → Rollback

**Topics Covered:**
- [6.2.1 Print Spooler service disabling — Finding H-04](#621-disable-print-spooler-on-domain-controllers)
- [6.2.2 Password policy strengthening — Finding H-01](#622-strengthen-password-policy)
- [6.2.3 Windows LAPS deployment — Finding H-03](#623-deploy-windows-laps)
- [6.3.1 Advanced audit policy implementation — Finding M-01](#631-apply-domain-controller-audit-baseline)
- [6.4.1 Admin delegation protection — Finding M-06](#641-protect-admin-accounts-from-delegation)
- [6.4.2 Schema Admins group management — Finding M-07](#642-empty-schema-admins-group)
- [6.5.1 AD Recycle Bin enablement — Finding L-01](#651-enable-ad-recycle-bin)
- [6.5.2 UNC hardened paths — Finding M-08](#652-configure-unc-hardened-paths)
- [6.5.3 AD Sites and Subnets — Finding M-05](#653-configure-ad-sites-and-subnets)
- [6.6.1 PowerShell logging](#661-enable-powershell-script-block-logging)

---

## 6.1 Configuration Hardening Strategy Overview

### Hardening Priorities

Configuration changes are prioritized based on risk severity and business impact:

| Priority | Risk Level | Timeline | Category |
|----------|-----------|----------|----------|
| Critical | HIGH | 0-14 days | Service hardening, passwords, LAPS |
| High | MEDIUM | 14-30 days | Audit policies, account protection |
| Medium | LOW | 30-90 days | Directory features, advanced security |

### Change Management

All configuration changes require:
- Impact assessment during audit period
- Stakeholder notification and approval
- Pilot OU testing (minimum 7 days)
- Domain-wide deployment only after successful pilot
- Documented rollback procedures

---

## 6.2 Phase 1: Critical Configuration Hardening (0-14 Days)

### 6.2.1 Disable Print Spooler on Domain Controllers

**Finding Reference:** HIGH risk finding H-04

**Risk Description:**

The Windows Print Spooler service is running on Domain Controllers despite no printing requirements. This creates unnecessary attack surface:
- **PrintNightmare (CVE-2021-34527):** Remote code execution vulnerability
- **PrintDemon:** Local privilege escalation
- Unnecessary service increases attack surface
- Domain Controllers rarely require printing functionality

**Business Impact:**
- Remote code execution risk on critical infrastructure
- Privilege escalation to SYSTEM on DCs
- Potential for domain compromise
- Violation of principle of least functionality

**Framework References:**
- CVE-2021-34527 (PrintNightmare)
- MITRE ATT&CK: T1187 (Forced Authentication)
- CIS Benchmark: Recommends disabling unnecessary services
- ISO 27001:2022 Control 8.8 (Technical Vulnerabilities)

**Detection:**

```powershell
# Check Print Spooler service status on Domain Controllers
$DCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Hostname
foreach ($dc in $DCs) {
    Get-Service -Name Spooler -ComputerName $dc | 
        Select-Object PSComputerName, Name, Status, StartType
}
```

Expected vulnerable output:
```
PSComputerName Name    Status  StartType
-------------- ----    ------  ---------
DC01           Spooler Running Automatic
DC02           Spooler Running Automatic
```

**Audit First:**

```powershell
# Check if any print jobs or printers configured on DCs
$DCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Hostname
foreach ($dc in $DCs) {
    Write-Host "Checking $dc for printers..."
    Get-Printer -ComputerName $dc -ErrorAction SilentlyContinue
    Get-PrintJob -ComputerName $dc -ErrorAction SilentlyContinue
}

# Verify no DC requires printing functionality (typical: none needed)
# Audit period: Immediate (no business impact expected)
```

**Impact Assessment:**
- Domain Controllers should NOT have printing requirements
- Verify no print management tools depend on Spooler service
- Immediate remediation recommended (no anticipated impact)

**Mitigation:**

**Group Policy Method (Recommended):**

Create or edit a GPO linked to Domain Controllers OU:

| Setting Path | Setting Name | Value |
|---|---|---|
| Computer Configuration → Policies → Windows Settings → Security Settings → System Services | Print Spooler | Disabled |

**PowerShell Alternative:**

```powershell
# Disable Print Spooler on all Domain Controllers
$DCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Hostname
foreach ($dc in $DCs) {
    Invoke-Command -ComputerName $dc -ScriptBlock {
        Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
        Set-Service -Name Spooler -StartupType Disabled
    }
}
```

**Verification:**

```powershell
$DCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Hostname
foreach ($dc in $DCs) {
    Get-Service -Name Spooler -ComputerName $dc | 
        Select-Object PSComputerName, Status, StartType
}
# Expected: Status = Stopped, StartType = Disabled
```

**Rollback:**

```powershell
$DCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Hostname
foreach ($dc in $DCs) {
    Set-Service -Name Spooler -StartupType Manual -ComputerName $dc
    Start-Service -Name Spooler -ComputerName $dc
}
```

---

### 6.2.2 Strengthen Password Policy

**Finding Reference:** HIGH risk finding H-01

**Risk Description:**

The domain password policy requires only 7-character passwords, significantly below modern security standards. Short passwords are susceptible to:
- Brute force attacks
- Dictionary attacks
- Rainbow table attacks
- Credential stuffing

**Business Impact:**
- Increased risk of account compromise
- Easier lateral movement after initial breach
- Non-compliance with most security frameworks (NIST, ISO 27001, PCI DSS)

**Framework References:**
- ISO 27001:2022 Controls 5.17, 5.18
- MITRE ATT&CK: T1201 (Password Policy Discovery)
- NIST SP 800-63B: Recommends minimum 8 characters (12+ for admin accounts)

**Detection:**

```powershell
# Check current domain password policy
Get-ADDefaultDomainPasswordPolicy | Select-Object `
    MinPasswordLength, 
    PasswordHistoryCount, 
    ComplexityEnabled, 
    MaxPasswordAge, 
    MinPasswordAge, 
    LockoutThreshold
```

Expected vulnerable output:
```
MinPasswordLength    : 7
PasswordHistoryCount : 24
ComplexityEnabled    : True
MaxPasswordAge       : 42.00:00:00
MinPasswordAge       : 1.00:00:00
LockoutThreshold     : 0
```

**Audit First:**

```powershell
# Identify users with potentially weak passwords (requires password auditing tool)
# Review fine-grained password policies if any
Get-ADFineGrainedPasswordPolicy -Filter *

# Notify users 48 hours before policy change
# Prepare helpdesk for increased password reset requests
```

**Impact Assessment:**
- Users with passwords shorter than 12 characters must change at next logon
- Communicate change 48 hours in advance
- Prepare helpdesk resources
- Consider phased rollout by OU

**Mitigation:**

**Group Policy Method (Recommended):**

Create or edit a GPO linked to Domain Root:

| Setting Path | Setting Name | Value |
|---|---|---|
| Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Password Policy | Minimum password length | 12 characters |
| Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Password Policy | Enforce password history | 24 passwords remembered |
| Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Password Policy | Password must meet complexity requirements | Enabled |
| Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Password Policy | Maximum password age | 90 days |
| Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Password Policy | Minimum password age | 1 days |
| Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Account Lockout Policy | Account lockout threshold | 10 invalid logon attempts |
| Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Account Lockout Policy | Account lockout duration | 15 minutes |
| Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Account Lockout Policy | Reset account lockout counter after | 15 minutes |

**PowerShell Alternative:**

```powershell
# Set minimum password length to 12 characters
Set-ADDefaultDomainPasswordPolicy -Identity "contoso.com" `
    -MinPasswordLength 12 `
    -PasswordHistoryCount 24 `
    -ComplexityEnabled $true `
    -MaxPasswordAge (New-TimeSpan -Days 90) `
    -MinPasswordAge (New-TimeSpan -Days 1) `
    -LockoutThreshold 10 `
    -LockoutDuration (New-TimeSpan -Minutes 15) `
    -LockoutObservationWindow (New-TimeSpan -Minutes 15)
```

**Verification:**

```powershell
Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength, LockoutThreshold
# Expected: MinPasswordLength = 12, LockoutThreshold = 10
```

**Rollback:**

```powershell
Set-ADDefaultDomainPasswordPolicy -Identity "contoso.com" -MinPasswordLength 7 -LockoutThreshold 0
```

---

### 6.2.3 Deploy Windows LAPS

**Finding Reference:** HIGH risk finding H-03

**Risk Description:**

Windows Local Administrator Password Solution (LAPS) is not configured. Without LAPS:
- Local administrator passwords are static across workstations
- Same password on multiple machines enables lateral movement
- Compromising one workstation exposes entire fleet
- No auditing of local administrator password access
- Manual password management is error-prone

**Business Impact:**
- Single compromised workstation allows lateral movement
- Difficult to rotate local admin passwords manually
- No audit trail for password usage
- Incident response challenges

**Framework References:**
- ISO 27001:2022 Controls 5.17 (Authentication Information), 5.18 (Access Rights)
- MITRE ATT&CK: T1078.003 (Valid Accounts: Local Accounts)
- CIS Control 5: Account Management

**Detection:**

```powershell
# Check if Windows LAPS is configured (native to Windows Server 2022)
# Check for LAPS registry settings
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" `
    -ErrorAction SilentlyContinue

# Check AD schema for LAPS attributes (Windows LAPS uses same attributes as legacy LAPS)
Get-ADObject "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,DC=contoso,DC=com" `
    -ErrorAction SilentlyContinue

# Check if any computers have LAPS passwords stored
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | 
    Where-Object {$_."ms-Mcs-AdmPwd" -ne $null} | 
    Select-Object Name, ms-Mcs-AdmPwd
```

Expected vulnerable output: No LAPS configuration found

**Audit First:**

```powershell
# Pilot deployment on test OU first
# Create test OU
New-ADOrganizationalUnit -Name "LAPS-Pilot" -Path "DC=contoso,DC=com"

# Move 2-3 test computers to pilot OU
Get-ADComputer "WS01" | Move-ADObject -TargetPath "OU=LAPS-Pilot,DC=contoso,DC=com"

# Monitor for 7 days:
# - Verify local admin access still works
# - Confirm password rotation occurs
# - Test password retrieval process
```

**Impact Assessment:**
- Test on pilot OU for 7 days
- Verify local admin access functionality
- Confirm password rotation successful
- No impact on domain users (only local admin account affected)
- Plan communication with IT support staff

**Mitigation:**

**Note:** Windows Server 2022 includes native Windows LAPS (built-in). No separate installation required.

**Group Policy Method (Recommended):**

Create or edit a GPO linked to Target Computers OU:

| Setting Path | Setting Name | Value |
|---|---|---|
| Computer Configuration → Administrative Templates → System → LAPS | Configure password backup directory | Backup the password to Active Directory only |
| Computer Configuration → Administrative Templates → System → LAPS | Password Settings | Complexity: 4, Length: 14, Age: 30 days |
| Computer Configuration → Administrative Templates → System → LAPS | Name of administrator account to manage | Administrator |

**PowerShell Alternative:**

```powershell
# Configure via PowerShell (on target computers):
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" `
    -Name "BackupDirectory" -Value 2 -PropertyType DWord -Force
# Value: 1 = Azure AD only, 2 = Active Directory only, 3 = Both

New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" `
    -Name "PasswordComplexity" -Value 4 -PropertyType DWord -Force

New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" `
    -Name "PasswordLength" -Value 14 -PropertyType DWord -Force

New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" `
    -Name "PasswordAgeDays" -Value 30 -PropertyType DWord -Force

# Set AD permissions for computers to update their own password
$ou = "OU=LAPS-Pilot,DC=contoso,DC=com"
$computers = Get-ADComputer -Filter * -SearchBase $ou
foreach ($computer in $computers) {
    $acl = Get-Acl "AD:$($computer.DistinguishedName)"
    # Grant SELF permission to write ms-Mcs-AdmPwd attribute
    # (Detailed ACL configuration omitted for brevity - see full implementation guide)
}
```

**Verification:**

```powershell
# Check LAPS configuration on a computer
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"

# Check if LAPS password is being stored in AD
Get-ADComputer "WS01" -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime | 
    Select-Object Name, ms-Mcs-AdmPwd, `
        @{N='PasswordExpires';E={[datetime]::FromFileTime($_.'ms-Mcs-AdmPwdExpirationTime')}}

# Force password rotation (for testing)
Invoke-Command -ComputerName WS01 -ScriptBlock {
    gpupdate /force
}
```

**Rollback:**

```powershell
# Disable Windows LAPS via GPO
# Computer Configuration → Administrative Templates → System → LAPS
# Set "Configure password backup directory" to "Disabled"

# Or via registry:
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" `
    -Name "BackupDirectory" -Force -ErrorAction SilentlyContinue
```

---

## 6.3 Phase 2: Advanced Audit Policy Implementation (14-30 Days)

### 6.3.1 Apply Domain Controller Audit Baseline

**Finding Reference:** MEDIUM risk finding M-01

**Risk:** Without comprehensive audit logging, security incidents go undetected and forensic analysis is impossible.

**Detection:**

```powershell
# Check current audit policy configuration
auditpol /get /category:* | Out-File C:\Temp\current_audit_policy.txt

# Review output for audit gaps
Get-Content C:\Temp\current_audit_policy.txt | Select-String "No Auditing"
```

**Audit First:**

```powershell
# Estimate log volume impact
# Advanced audit policy increases log volume 3-5x
# Check current Security log size and retention

Get-WinEvent -LogName Security -MaxEvents 1 | 
    Select-Object @{N='LogSize';E={(Get-WinEvent -LogName Security -Oldest -MaxEvents 1).TimeCreated}}, `
                  @{N='OldestEvent';E={(Get-WinEvent -LogName Security -Oldest -MaxEvents 1).TimeCreated}}, `
                  @{N='NewestEvent';E={(Get-WinEvent -LogName Security -MaxEvents 1).TimeCreated}}

# Test on one DC first for 7 days
# Monitor SIEM log ingestion capacity
```

**Impact Assessment:**

- SIEM storage requirements (estimate 3-5x increase)
- Log retention policy review
- SIEM parsing and alerting configuration
- Disk space on Domain Controllers

**Mitigation:**

**Group Policy Method (Recommended):**

Create or edit a GPO linked to Domain Controllers OU:

| Setting Path | Setting Name | Value |
|---|---|---|
| Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Account Logon | Credential Validation | Success, Failure |
| Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → DS Access | Directory Service Changes | Success, Failure |
| Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Logon/Logoff | Logon | Success, Failure |
| Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration | (Full list in Appendix D) | Success, Failure |

**PowerShell Alternative:**

```powershell
# Apply Advanced Audit Policy via auditpol commands

# Account Logon
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

# Account Management
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable

# DS Access (Directory Service Access - critical for DCs)
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

# Logon/Logoff
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable

# Object Access (for SYSVOL/NETLOGON if needed)
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable

# Policy Change
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable

# Privilege Use
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# System
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
```

**Alternative: Apply via Group Policy**

```
Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration
```

Navigate to each subcategory and configure:
- Account Logon → Credential Validation: Success, Failure
- DS Access → Directory Service Changes: Success, Failure
- Logon/Logoff → Logon: Success, Failure
- (Full list in Appendix D: GPO Baseline Configuration)

**Verification:**

```powershell
# Verify audit policy applied
auditpol /get /category:"Account Logon" | Select-String "Credential Validation"
# Expected: Success and Failure

auditpol /get /category:"DS Access" | Select-String "Directory Service Changes"
# Expected: Success and Failure

# Check that events are being generated
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4768,4769,5136,5137} -MaxEvents 20
# Events:
# 4768: Kerberos TGT requested
# 4769: Kerberos service ticket requested
# 5136: Directory Service object modified
# 5137: Directory Service object created
```

**Rollback:**

```powershell
# Reset to default (minimal) audit policy
auditpol /clear /y
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
# Apply only minimal auditing
```

---

## 6.4 Phase 3: Privileged Account Protection (14-30 Days)

### 6.4.1 Protect Admin Accounts from Delegation

**Finding Reference:** MEDIUM risk finding M-06

**Risk:** Without "sensitive and cannot be delegated" flag, admin accounts vulnerable to delegation attacks.

**Detection:**

```powershell
# Find admin accounts without delegation protection
Get-ADUser -Filter {AdminCount -eq 1} -Properties AccountNotDelegated | 
    Where-Object {$_.AccountNotDelegated -eq $false} | 
    Select-Object Name, SamAccountName, AccountNotDelegated, AdminCount
```

**Audit First:**

```powershell
# Review if any legitimate delegation scenarios exist for admin accounts
# Document delegation requirements
# Typically, administrative accounts should NEVER be delegated
```

**Impact Assessment:**

Should have minimal impact - administrators should not be using delegation. If any admin account requires delegation, investigate why (likely misconfiguration).

**Mitigation:**

```powershell
# Set "Account is sensitive and cannot be delegated" flag for all admin accounts
Get-ADUser -Filter {AdminCount -eq 1} | 
    Set-ADAccountControl -AccountNotDelegated $true

# Alternatively, add eligible accounts to Protected Users group
# Protected Users group (Windows Server 2012 R2+) provides additional protections:
# - Forces Kerberos authentication (no NTLM, DES, RC4)
# - Cannot be delegated
# - TGT lifetime limited to 4 hours

Add-ADGroupMember -Identity "Protected Users" -Members "ahmed.bayoumy"

# WARNING: Protected Users has strict requirements:
# - Kerberos-only authentication
# - May break some applications/services
# - Test thoroughly before adding all admins
```

**Verification:**

```powershell
# Verify AccountNotDelegated flag set
Get-ADUser -Filter {AdminCount -eq 1} -Properties AccountNotDelegated | 
    Select-Object Name, AccountNotDelegated
# All should show: AccountNotDelegated = True

# Verify Protected Users membership
Get-ADGroupMember "Protected Users" | Select-Object Name
```

**Rollback:**

```powershell
# Remove delegation protection (not recommended)
Get-ADUser -Filter {AdminCount -eq 1} | 
    Set-ADAccountControl -AccountNotDelegated $false

# Remove from Protected Users
Remove-ADGroupMember -Identity "Protected Users" -Members "ahmed.bayoumy" -Confirm:$false
```

---

### 6.4.2 Empty Schema Admins Group

**Finding Reference:** MEDIUM risk finding M-07

**Risk:** Persistent membership in Schema Admins increases attack surface (schema modifications are rare).

**Detection:**

```powershell
# Check Schema Admins group membership
Get-ADGroupMember "Schema Admins" | Select-Object Name, SamAccountName
```

**Audit First:**

```powershell
# Document current members and justification
# Establish just-in-time (JIT) access process for schema changes
# Schema modifications should be rare and controlled
```

**Impact Assessment:**

No impact - schema changes are infrequent. Implement just-in-time access:
1. Remove all permanent members
2. Add account only when schema modification needed
3. Remove account immediately after change
4. Document and approve all schema changes

**Mitigation:**

```powershell
# Remove all members from Schema Admins group
Get-ADGroupMember "Schema Admins" | ForEach-Object {
    Remove-ADGroupMember "Schema Admins" -Members $_ -Confirm:$false
}

# Document JIT access procedure:
# 1. Request schema change approval
# 2. Temporarily add account: Add-ADGroupMember "Schema Admins" -Members "admin.account"
# 3. Perform schema modification
# 4. Immediately remove: Remove-ADGroupMember "Schema Admins" -Members "admin.account"
# 5. Audit schema change via Event 4662 (DS Access)
```

**Verification:**

```powershell
Get-ADGroupMember "Schema Admins"
# Should return no members (empty group)

# Enable audit of Schema Admins group membership changes
# Event ID 4728: Member added to security-enabled global group
# Event ID 4729: Member removed from security-enabled global group
```

**Rollback:**

```powershell
# Re-add specific account if needed (temporarily)
Add-ADGroupMember "Schema Admins" -Members "Administrator"
```

---

## 6.5 Phase 4: Directory Resilience and Advanced Features (30-90 Days)

### 6.5.1 Enable AD Recycle Bin

**Finding Reference:** LOW risk finding L-01

**Risk Description:**

Active Directory Recycle Bin is not enabled, limiting recovery options for accidentally deleted objects.

**Impact:**
- Deleted AD objects difficult to restore
- Requires authoritative restore from backup (downtime)
- Some attributes lost even with tombstone reanimation

**Framework References:**
- ISO 27001:2022 Control 8.13 (Information Backup)
- Best practice for directory resilience

**Detection:**

```powershell
(Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"').EnabledScopes
# If empty, Recycle Bin is not enabled
```

**Audit:**

```powershell
# Review forest functional level requirements (Windows Server 2008 R2+)
(Get-ADForest).ForestMode
# WARNING: Enabling AD Recycle Bin is a one-way, irreversible operation
```

**Mitigation:**

```powershell
# Enable AD Recycle Bin (IRREVERSIBLE - cannot be disabled)
Enable-ADOptionalFeature -Identity "Recycle Bin Feature" `
    -Scope ForestOrConfigurationSet -Target "contoso.com" -Confirm:$false
```

**Verification:**

```powershell
(Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"').EnabledScopes
# Should return forest DN: DC=contoso,DC=com
```

**Impact Assessment:** No negative impact, improves recovery capability. One-way operation (cannot be reversed).

---

### 6.5.2 Configure UNC Hardened Paths

**Finding Reference:** MEDIUM risk finding M-08

**Risk:** Without UNC hardened paths, connections to SYSVOL and NETLOGON vulnerable to man-in-the-middle attacks.

**Detection:**

```powershell
# Check if UNC hardened paths configured
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" `
    -ErrorAction SilentlyContinue
```

**Audit First:**

```powershell
# Test in pilot OU for 48 hours
# Monitor for UNC path access issues
# Should have no impact (modern Windows supports)
```

**Impact Assessment:**

Minimal impact - improves security of UNC connections to domain resources. All modern Windows versions support hardened UNC paths.

**Mitigation:**

**Group Policy Method (Recommended):**

Create or edit a GPO linked to Domain Root:

| Setting Path | Setting Name | Value |
|---|---|---|
| Computer Configuration → Administrative Templates → Network → Network Provider | Hardened UNC Paths | Enabled. Add paths: \\\\*\\SYSVOL (RequireMutualAuthentication=1,RequireIntegrity=1) and \\\\*\\NETLOGON (RequireMutualAuthentication=1,RequireIntegrity=1) |

**PowerShell Alternative:**

```powershell
# Configure UNC hardened paths via registry
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Force | Out-Null

# Require mutual authentication and integrity for SYSVOL
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" `
    -Name "\\*\SYSVOL" -Value "RequireMutualAuthentication=1,RequireIntegrity=1" -Type String

# Require mutual authentication and integrity for NETLOGON
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" `
    -Name "\\*\NETLOGON" -Value "RequireMutualAuthentication=1,RequireIntegrity=1" -Type String
```

**Verification:**

```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
# Should show both SYSVOL and NETLOGON paths configured

# Test SYSVOL access (should still work)
Test-Path "\\contoso.com\SYSVOL"
# Expected: True
```

**Rollback:**

```powershell
Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Recurse -Force
```

---

### 6.5.3 Configure AD Sites and Subnets

**Finding Reference:** MEDIUM risk finding M-05

**Risk:** Missing AD Sites and Subnets configuration leads to inefficient replication and authentication.

**Detection:**

```powershell
# Check existing AD Sites
Get-ADReplicationSite -Filter * | Select-Object Name, Description

# Check existing subnets
Get-ADReplicationSubnet -Filter * | Select-Object Name, Site, Location

# Check where DCs reside
Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, Site
```

**Audit First:**

```powershell
# Document current DC IP addresses and network subnets
Get-ADDomainController -Filter * | 
    Select-Object Name, IPv4Address, Site | 
    Export-Csv C:\Temp\DC_IP_Addresses.csv -NoTypeInformation

# Review network topology
# Identify subnets where DCs and clients reside
```

**Impact Assessment:**

Minimal impact - improves replication efficiency and client authentication performance. Proper AD Sites configuration ensures clients authenticate to nearest DC.

**Mitigation:**

```powershell
# Add missing subnets to default site (or create new sites if multi-site environment)

# For lab environment (single site):
New-ADReplicationSubnet -Name "192.168.51.0/24" -Site "Default-First-Site-Name"

# For multi-site environment:
# 1. Create new sites
New-ADReplicationSite -Name "Branch-Office-Site" -Description "Branch Office Location"

# 2. Create site links
New-ADReplicationSiteLink -Name "HQ-to-Branch" `
    -SitesIncluded "Default-First-Site-Name","Branch-Office-Site" `
    -Cost 100 -ReplicationFrequencyInMinutes 180

# 3. Associate subnets with sites
New-ADReplicationSubnet -Name "192.168.52.0/24" -Site "Branch-Office-Site"
```

**Verification:**

```powershell
# Verify subnet configuration
Get-ADReplicationSubnet -Filter * | Select-Object Name, Site
# All DC subnets should be listed

# Verify DCs assigned to correct sites
Get-ADDomainController -Filter * | Select-Object Name, Site

# Test client site assignment
nltest /dsgetsite
# Should return correct site based on client IP
```

**Rollback:**

```powershell
# Remove subnet (if misconfigured)
Remove-ADReplicationSubnet -Identity "192.168.51.0/24" -Confirm:$false
```

---

## 6.6 Additional Security Enhancements

### 6.6.1 Enable PowerShell Script Block Logging

**Risk:** Without PowerShell logging, malicious scripts execute undetected.

**Detection:**

```powershell
# Check if PowerShell script block logging enabled
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue

# Check module logging
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -Name "EnableModuleLogging" -ErrorAction SilentlyContinue
```

**Audit First:**

```powershell
# Estimate log volume (PowerShell logs can be high volume)
# Check SIEM capacity for PowerShell logs
# Estimate: 100-500 MB/day per server depending on usage
```

**Mitigation:**

**Group Policy Method (Recommended):**

Create or edit a GPO linked to Domain Root:

| Setting Path | Setting Name | Value |
|---|---|---|
| Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell | Turn on PowerShell Script Block Logging | Enabled |
| Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell | Turn on Module Logging | Enabled |

**PowerShell Alternative:**

```powershell
# Enable Script Block Logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

# Enable Module Logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -Name "EnableModuleLogging" -Value 1 -Type DWord

# Specify modules to log (optional - log all by default)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" `
    -Name "*" -Value "*" -Type String
```

**Verification:**

```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging"
# Expected: 1

# Test logging - run a PowerShell command and check logs
Get-Process
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 5 | 
    Where-Object {$_.Id -eq 4104} | 
    Select-Object TimeCreated, Message
# Event ID 4104: Script block text logging
```

**Rollback:**

```powershell
Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Recurse -Force
Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Recurse -Force
```


## 6.7 Configuration Hardening Summary

### Implemented Configurations

This chapter detailed the following configuration hardening measures:

| Configuration | Finding | Risk Level | Implementation | Timeline |
|---------------|---------|-----------|----------------|----------|
| Print Spooler disabled | H-04 | HIGH | GPO System Services | 0-14 days |
| Strong password policy | H-01 | HIGH | Default Domain Policy | 0-14 days |
| LAPS deployment | H-03 | HIGH | GPO + AD schema | 0-14 days |
| Advanced audit policies | M-01 | MEDIUM | auditpol / GPO | 14-30 days |
| Admin delegation protection | M-06 | MEDIUM | AccountNotDelegated flag | 14-30 days |
| Schema Admins empty | M-07 | MEDIUM | JIT access model | 14-30 days |
| AD Recycle Bin | L-01 | LOW | Optional feature | 30-90 days |
| UNC hardened paths | M-08 | MEDIUM | Registry / GPO | 30-90 days |
| AD Sites and Subnets | M-05 | MEDIUM | AD topology | 30-90 days |
| PowerShell logging | — | Enhancement | Script block logging | 30-90 days |

### Compliance Achievements

**ISO 27001:2022 Controls:**
- Control 5.17 (Authentication): Password policy, LAPS
- Control 5.18 (Access Rights): Admin protection, delegation
- Control 8.2 (Privileged Access): Admin account hardening
- Control 8.8 (Technical Vulnerabilities): Service hardening
- Control 8.13 (Information Backup): AD Recycle Bin
- Control 8.15 (Logging): Advanced audit policies, PowerShell logging

**MITRE ATT&CK Mitigations:**
- T1078.003 (Local Accounts): LAPS, gMSA
- T1187 (Forced Authentication): Print Spooler disabled
- Credential Access techniques: Protected accounts, audit logging

---

## Summary

This chapter implemented comprehensive configuration hardening and security enhancements:

- **Critical Hardening:** Print Spooler disabled, strong passwords, LAPS deployed
- **Privileged Access:** Admin accounts protected from delegation, Schema Admins emptied
- **Audit & Monitoring:** Advanced audit policies, PowerShell logging enabled
- **Directory Resilience:** AD Recycle Bin, Sites/Subnets, UNC hardened paths
- **Advanced Security:** Group Managed Service Accounts for password-less service authentication

All changes followed audit-first methodology with documented rollback procedures. The next chapter analyzes the results and security improvements achieved.

---

[← Previous: Mitigating Insecure Protocols and Authentication](05-protocol-remediation.md) | [Next: Additional Hardening Actions →](07-additional-hardening-actions.md)

---

## Resources

- Password policy settings: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-policies-password-policy
- Windows LAPS technical reference: https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference
- Advanced security audit policy settings: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings
- Active Directory Recycle Bin overview: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-recycle-bin
- Print Spooler service security: https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server
- Group Managed Service Accounts: https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview
