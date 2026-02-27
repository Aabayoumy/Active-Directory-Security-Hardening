# Chapter 6: Configuration Hardening and Security Enhancements

[← Previous: Mitigating Insecure Protocols and Authentication](05-protocol-remediation.md) | [Next: Results and Analysis →](07-results-analysis.md)

---

## Chapter Overview

This chapter addresses security hardening through configuration changes, security feature deployment, and best practice implementations. Building on the protocol remediations in Chapter 5, this chapter focuses on system configuration, privileged access management, audit policies, and directory resilience.

**All remediations follow the standardized workflow:**
- Detection → Audit → Impact Assessment → Mitigation → Verification → Rollback

**Topics Covered:**
- Print Spooler service disabling (covered in Chapter 4, H-04)
- Password policy strengthening (covered in Chapter 4, H-01)
- Windows LAPS deployment (covered in Chapter 4, H-03)
- Advanced audit policy implementation
- Privileged account protection
- AD Recycle Bin enablement
- UNC hardened paths
- Group Managed Service Accounts (gMSA)
- PowerShell logging
- Schema Admins group management
- AD Sites and Subnets configuration

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

**Finding Reference:** HIGH risk finding H-04 (detailed in Chapter 4)

This remediation was fully detailed in Chapter 4, Section 4.4 (H-04). Summary:

**Quick Reference:**

```powershell
# Detection
Get-Service -Name Spooler -ComputerName DC01,DC02

# Mitigation
$DCs = @("DC01","DC02")
foreach($dc in $DCs){
    Invoke-Command -ComputerName $dc -ScriptBlock {
        Stop-Service -Name Spooler -Force
        Set-Service -Name Spooler -StartupType Disabled
    }
}

# Verification
Get-Service -Name Spooler -ComputerName DC01,DC02 | Select-Object PSComputerName,Status,StartType
# Expected: Status=Stopped, StartType=Disabled
```

Refer to Chapter 4, Section 4.4, Finding H-04 for complete implementation details.

---

### 6.2.2 Strengthen Password Policy

**Finding Reference:** HIGH risk finding H-01 (detailed in Chapter 4)

This remediation was fully detailed in Chapter 4, Section 4.4 (H-01). Summary:

**Quick Reference:**

```powershell
# Detection
Get-ADDefaultDomainPasswordPolicy

# Mitigation
Set-ADDefaultDomainPasswordPolicy -Identity "contoso.com" `
    -MinPasswordLength 12 `
    -PasswordHistoryCount 24 `
    -ComplexityEnabled $true `
    -MaxPasswordAge (New-TimeSpan -Days 90) `
    -MinPasswordAge (New-TimeSpan -Days 1) `
    -LockoutThreshold 10 `
    -LockoutDuration (New-TimeSpan -Minutes 15)

# Verification
Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength,LockoutThreshold
# Expected: MinPasswordLength=12, LockoutThreshold=10
```

Refer to Chapter 4, Section 4.4, Finding H-01 for complete implementation details.

---

### 6.2.3 Deploy Windows LAPS

**Finding Reference:** HIGH risk finding H-03 (detailed in Chapter 4)

This remediation was fully detailed in Chapter 4, Section 4.4 (H-03). Summary:

**Quick Reference:**

Windows Server 2022 includes native Windows LAPS (no separate installation required).

```powershell
# Detection
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ErrorAction SilentlyContinue

# Mitigation (configure via GPO or PowerShell)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" `
    -Name "BackupDirectory" -Value 2 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" `
    -Name "PasswordLength" -Value 14 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" `
    -Name "PasswordAgeDays" -Value 30 -PropertyType DWord -Force

# Verification
Get-ADComputer "WS01" -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime
```

Refer to Chapter 4, Section 4.4, Finding H-03 for complete implementation details including AD permissions.

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

```powershell
# Apply Advanced Audit Policy via auditpol commands
# Or via Group Policy: Computer Configuration → Security Settings → Advanced Audit Policy

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

**Finding Reference:** LOW risk finding L-01 (detailed in Chapter 4)

This remediation was detailed in Chapter 4, Section 4.6 (L-01). Summary:

**Quick Reference:**

```powershell
# Detection
(Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"').EnabledScopes

# Mitigation (IRREVERSIBLE)
Enable-ADOptionalFeature -Identity "Recycle Bin Feature" `
    -Scope ForestOrConfigurationSet -Target "contoso.com" -Confirm:$false

# Verification
(Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"').EnabledScopes
# Should return: DC=contoso,DC=com
```

**Important:** This is a one-way operation and cannot be reversed. Requires Windows Server 2008 R2+ forest functional level.

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

```powershell
# Configure UNC hardened paths via registry
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Force | Out-Null

# Require mutual authentication and integrity for SYSVOL
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" `
    -Name "\\*\SYSVOL" -Value "RequireMutualAuthentication=1,RequireIntegrity=1" -Type String

# Require mutual authentication and integrity for NETLOGON
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" `
    -Name "\\*\NETLOGON" -Value "RequireMutualAuthentication=1,RequireIntegrity=1" -Type String

# Or via Group Policy (preferred):
# Computer Configuration → Administrative Templates → Network → Network Provider
# "Hardened UNC Paths" = Enabled
# Add paths:
# \\*\SYSVOL     RequireMutualAuthentication=1,RequireIntegrity=1
# \\*\NETLOGON   RequireMutualAuthentication=1,RequireIntegrity=1
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

# Or via Group Policy:
# Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell
# "Turn on PowerShell Script Block Logging" = Enabled
# "Turn on Module Logging" = Enabled
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

---

### 6.6.2 Implement Group Managed Service Accounts (gMSA)

**Risk:** Traditional service accounts with static passwords vulnerable to credential theft.

**Detection:**

```powershell
# Check if KDS root key exists (required for gMSA)
Get-KdsRootKey

# Check existing service accounts
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName | 
    Select-Object Name, SamAccountName, ServicePrincipalName
```

**Audit First:**

```powershell
# Identify service accounts to migrate to gMSA
# Plan migration per service
# Document applications using service accounts
```

**Mitigation:**

```powershell
# Step 1: Create KDS root key (required for gMSA)
# NOTE: In production, key takes 10 hours to replicate. For testing, use -EffectiveImmediately
Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))

# Step 2: Create security group for servers that will use gMSA
New-ADGroup -Name "WebServers-Group" -GroupScope Global -GroupCategory Security `
    -Path "OU=Groups,DC=contoso,DC=com"

# Add member servers to group
Add-ADGroupMember -Identity "WebServers-Group" -Members (Get-ADComputer "WS01")

# Step 3: Create gMSA
New-ADServiceAccount -Name "svc-webapp-gmsa" `
    -DNSHostName "webapp.contoso.com" `
    -PrincipalsAllowedToRetrieveManagedPassword "WebServers-Group" `
    -ServicePrincipalNames "HTTP/webapp.contoso.com"

# Step 4: Install gMSA on target server
Invoke-Command -ComputerName WS01 -ScriptBlock {
    Install-ADServiceAccount -Identity "svc-webapp-gmsa"
}

# Step 5: Configure service to use gMSA
# In Services.msc, set service logon to: contoso\svc-webapp-gmsa$
# Leave password blank (gMSA manages password automatically)
```

**Verification:**

```powershell
# Verify gMSA created
Get-ADServiceAccount -Filter * | Select-Object Name, Enabled, ServicePrincipalNames

# Verify gMSA installed on server
Invoke-Command -ComputerName WS01 -ScriptBlock {
    Test-ADServiceAccount -Identity "svc-webapp-gmsa"
}
# Expected: True

# Verify password rotation (automatic, 30-day cycle by default)
Get-ADServiceAccount "svc-webapp-gmsa" -Properties PrincipalsAllowedToRetrieveManagedPassword
```

**Rollback:**

```powershell
# Remove gMSA from server
Invoke-Command -ComputerName WS01 -ScriptBlock {
    Uninstall-ADServiceAccount -Identity "svc-webapp-gmsa"
}

# Remove gMSA from AD
Remove-ADServiceAccount -Identity "svc-webapp-gmsa" -Confirm:$false
```

---

## 6.7 Configuration Hardening Summary

### Implemented Configurations

This chapter detailed the following configuration hardening measures:

| Configuration | Risk Level | Implementation | Status |
|---------------|-----------|----------------|--------|
| Print Spooler disabled | HIGH | Chapter 4, H-04 | Critical |
| Strong password policy | HIGH | Chapter 4, H-01 | Critical |
| LAPS deployment | HIGH | Chapter 4, H-03 | Critical |
| Advanced audit policies | MEDIUM | auditpol / GPO | High priority |
| Admin delegation protection | MEDIUM | AccountNotDelegated flag | High priority |
| Schema Admins empty | MEDIUM | JIT access model | High priority |
| UNC hardened paths | MEDIUM | Registry / GPO | High priority |
| AD Sites and Subnets | MEDIUM | AD topology | High priority |
| AD Recycle Bin | LOW | Optional feature | Enhancement |
| PowerShell logging | Enhancement | Script block logging | Enhancement |
| gMSA implementation | Enhancement | Service account security | Enhancement |

### Compliance Achievements

**ISO 27001:2022 Controls:**
- ✓ Control 5.17 (Authentication): Password policy, LAPS
- ✓ Control 5.18 (Access Rights): Admin protection, delegation
- ✓ Control 8.2 (Privileged Access): Admin account hardening
- ✓ Control 8.8 (Technical Vulnerabilities): Service hardening
- ✓ Control 8.13 (Information Backup): AD Recycle Bin
- ✓ Control 8.15 (Logging): Advanced audit policies, PowerShell logging

**MITRE ATT&CK Mitigations:**
- ✓ T1078.003 (Local Accounts): LAPS, gMSA
- ✓ T1187 (Forced Authentication): Print Spooler disabled
- ✓ Credential Access techniques: Protected accounts, audit logging

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

[← Previous: Mitigating Insecure Protocols and Authentication](05-protocol-remediation.md) | [Next: Results and Analysis →](07-results-analysis.md)
