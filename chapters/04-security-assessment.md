# Chapter 4: Security Configuration Assessment and Risk Analysis

[← Previous: Laboratory Environment](03-lab-environment.md) | [Next: Mitigating Insecure Protocols and Authentication →](05-protocol-remediation.md)

---

## 4.1 Assessment Overview

This chapter presents the findings from an automated security configuration assessment of the contoso.com Active Directory domain performed using Netwrix PingCastle Basic Edition.

### Assessment Details

- **Assessment Tool:** Netwrix PingCastle Basic Edition 3.4.1.38
- **Assessment Date:** 7 December 2025
- **Target Domain:** contoso.com
- **Target Platform:** Windows Server 2022 (November 2025 build)
- **Configuration State:** Default installation (no hardening applied)
- **Assessment Type:** Configuration security analysis (NO penetration testing or exploitation)

### Domain Health Score

**Overall Health Score: 77/100**

**Risk Level: HIGH**

The domain health score of 77/100 indicates significant security gaps in the default Active Directory configuration. PingCastle uses a 0-100 scale where:
- 90-100: Excellent security posture
- 80-89: Good security with minor improvements needed
- 70-79: Moderate security with important gaps (HIGH risk)
- 60-69: Poor security requiring urgent attention (CRITICAL risk)
- <60: Very poor security (CRITICAL risk)

A score of 77 places the domain in the HIGH risk category, requiring immediate attention to critical findings.

---

## 4.2 Assessment Methodology

PingCastle employs automated configuration discovery and rule-based analysis to assess Active Directory security:

### Assessment Process

1. **Configuration Discovery:**
   - LDAP queries to enumerate domain objects
   - Registry queries on Domain Controllers
   - Group Policy analysis
   - Certificate template review
   - DNS zone configuration checks

2. **Rule-Based Analysis:**
   - Compares discovered configuration against security best practices
   - Maps findings to risk categories
   - Assigns severity levels (HIGH, MEDIUM, LOW)
   - Calculates domain health score

3. **Framework Alignment:**
   - ISO/IEC 27001:2022 control mapping
   - MITRE ATT&CK technique identification
   - Compliance framework references

### Focus Areas

PingCastle assessed the following security domains:

#### 1. Authentication Protocols and Password Policies
- LM and NTLMv1 authentication support
- Password policy strength
- Account lockout configuration
- Kerberos encryption types

#### 2. Group Policy Objects (GPOs) Security Settings
- Password policy GPO settings
- Security options configuration
- Audit policy settings
- Service configuration via GPO

#### 3. Active Directory Certificate Services (ADCS/PKI)
- Certificate Authority configuration
- Certificate template permissions
- Web enrollment security (HTTP vs HTTPS)
- Certificate request approval requirements

#### 4. DNS Security Configuration
- DNSSEC implementation
- DNS zone transfer restrictions
- Dynamic update security

#### 5. Privileged Group Memberships and Delegations
- Schema Admins membership
- Enterprise Admins membership
- Domain Admins membership
- Custom delegations and ACLs
- "Account is sensitive and cannot be delegated" flag

#### 6. Domain Controller Security Settings
- Service configuration (Print Spooler)
- LDAP signing requirements
- LDAPS channel binding
- SMB signing configuration
- NTLM restrictions

### Limitations

**What PingCastle Does NOT Do:**
- No exploitation or attack simulation
- No password cracking or hash dumping
- No network traffic interception
- No vulnerability scanning of applications
- No penetration testing activities

PingCastle is a **configuration assessment tool**, not a penetration testing tool. It identifies security risks through configuration analysis and comparison to security baselines.

---

## 4.3 Risk Assessment Summary

The PingCastle assessment identified **14 security configuration issues** across the contoso.com domain.

### Risk Breakdown

| Risk Level | Count | Percentage | Remediation Timeline |
|------------|-------|-----------|----------------------|
| **HIGH** | 5 | 36% | Immediate (0-14 days) |
| **MEDIUM** | 8 | 57% | Short-term (14-30 days) |
| **LOW** | 1 | 7% | Long-term (30-90 days) |
| **Total** | **14** | **100%** | |

### Risk Distribution by Category

| Category | HIGH | MEDIUM | LOW | Total |
|----------|------|--------|-----|-------|
| Authentication & Passwords | 2 | 0 | 0 | 2 |
| Privileged Access | 1 | 3 | 0 | 4 |
| Services & Protocols | 2 | 3 | 0 | 5 |
| Directory & PKI | 0 | 2 | 1 | 3 |

### Framework Alignment

#### ISO/IEC 27001:2022 Controls

The findings map to the following ISO 27001:2022 controls:

- **Control 5.17 (Authentication Information):** Password policy, LAPS
- **Control 5.18 (Access Rights):** Privileged account protection, delegation
- **Control 5.34 (Privacy and Protection of PII):** Audit logging
- **Control 8.2 (Privileged Access Rights):** Admin account management
- **Control 8.5 (Secure Authentication):** NTLM restrictions, LDAP signing
- **Control 8.8 (Management of Technical Vulnerabilities):** Service hardening
- **Control 8.15 (Logging):** Audit policies
- **Control 8.24 (Use of Cryptography):** LDAPS, encryption

#### MITRE ATT&CK Techniques

The findings help mitigate the following ATT&CK techniques:

- **T1078.003 (Valid Accounts: Local Accounts):** LAPS deployment
- **T1187 (Forced Authentication):** Print Spooler, RPC coercion
- **T1201 (Password Policy Discovery):** Strong password policies
- **T1557 (Adversary-in-the-Middle):** LDAP signing, LDAPS
- **T1557.001 (LLMNR/NBT-NS Poisoning):** Name resolution hardening

---

## 4.4 HIGH Risk Findings

This section details the 5 HIGH-risk findings that require immediate remediation (0-14 days).

Each finding includes:
- **Detection:** PowerShell command to verify the vulnerability
- **Audit First:** Enable monitoring to identify business impact
- **Mitigation:** Step-by-step remediation instructions
- **Verification:** Confirm successful implementation

### H-01: Weak Password Policy (Minimum 7 characters)

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

### H-02: NTLMv1/LM Authentication Enabled

**Risk Description:**

The domain allows legacy NTLM version 1 and LAN Manager (LM) authentication protocols. These protocols have severe cryptographic weaknesses:
- LM uses weak DES encryption
- NTLMv1 vulnerable to pass-the-hash attacks
- No mutual authentication
- Susceptible to relay attacks
- Hashes can be cracked offline

**Business Impact:**
- Credentials vulnerable to interception and replay
- Lateral movement enabled after initial compromise
- Pass-the-hash attacks possible
- Non-compliance with modern security standards

**Framework References:**
- ISO 27001:2022 Control 8.5 (Secure Authentication)
- MITRE ATT&CK: T1557.001 (LLMNR/NBT-NS Poisoning), T1550.002 (Pass the Hash)
- CIS Benchmark: Requires NTLMv2 minimum (Level 1), Kerberos preferred (Level 2)

**Detection:**

```powershell
# Check LM Authentication Level (0-5 scale)
$lmLevel = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue

if ($lmLevel) {
    Write-Host "LmCompatibilityLevel: $($lmLevel.LmCompatibilityLevel)"
} else {
    Write-Host "LmCompatibilityLevel: Not Set (Default = 3, allows NTLMv1)"
}

# Level 0-2: LM and NTLMv1 allowed (VULNERABLE)
# Level 3: NTLMv2 preferred but NTLMv1 accepted (VULNERABLE)
# Level 4: NTLMv2 required, refuse LM
# Level 5: NTLMv2 required, refuse LM and NTLMv1 (SECURE)
```

**Audit First (CRITICAL - DO THIS FIRST):**

```powershell
# Enable NTLM auditing to identify systems using NTLMv1
# Apply via GPO or registry on all DCs

# Enable incoming NTLM traffic auditing
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
    -Name "AuditReceivingNTLMTraffic" -Value 2 -PropertyType DWord -Force
# Value 1 = Enable for domain accounts, 2 = Enable for all accounts

# Enable NTLM authentication auditing in domain
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
    -Name "RestrictReceivingNTLMTraffic" -Value 1 -PropertyType DWord -Force
# Value 1 = Audit, 2 = Block

# Monitor Event Viewer for 48-72 hours
# Event ID 8004: NTLM authentication attempts
Get-WinEvent -FilterHashtable @{LogName='System';ID=8004,8005,8006} -MaxEvents 100 | 
    Format-Table TimeCreated, Message -AutoSize

# Also check Security log Event ID 4624 (Logon) - check Authentication Package field
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 1000 | 
    Where-Object {$_.Message -like "*NTLM*"} | 
    Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}}, `
        @{N='Workstation';E={$_.Properties[11].Value}}
```

**Impact Assessment:**
- Monitor NTLM usage for 48-72 hours minimum
- Identify applications/systems using NTLM
- Contact application owners before enforcement
- Document legacy dependencies requiring NTLM
- Plan exceptions or mitigation (e.g., application updates)

**Mitigation:**

```powershell
# Set LM Authentication Level to 5 (Send NTLMv2 only, refuse LM & NTLMv1)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LmCompatibilityLevel" -Value 5 -Type DWord

# Apply via Group Policy (preferred for domain-wide):
# Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options
# "Network security: LAN Manager authentication level" = "Send NTLMv2 response only. Refuse LM & NTLM"

# Force Group Policy update
gpupdate /force
```

**Verification:**

```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel"
# Expected: LmCompatibilityLevel = 5

# Verify GPO application
Get-GPResultantSetOfPolicy -ReportType Html -Path C:\Temp\GPResult.html
# Check Security Options section for LAN Manager authentication level
```

**Rollback:**

```powershell
# Revert to default (level 3)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LmCompatibilityLevel" -Value 3
```

---

### H-03: LAPS Not Deployed

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

```powershell
# Configure Windows LAPS via Group Policy:
# Computer Configuration → Administrative Templates → System → LAPS

# 1. Enable Password Backup
# Setting: "Configure password backup directory"
# Value: "Backup the password to Active Directory only"

# 2. Configure Password Settings
# Setting: "Password Settings"
# - Password Complexity: 4 (Large + small + numbers + specials)
# - Password Length: 14
# - Password Age (Days): 30

# 3. Set Administrator Account Name
# Setting: "Name of administrator account to manage"
# Value: "Administrator"

# Alternatively, configure via PowerShell (on target computers):
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

### H-04: Print Spooler Service Active on Domain Controllers

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
$DCs = @("DC01", "DC02")
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

```powershell
# Disable Print Spooler on all Domain Controllers
$DCs = @("DC01", "DC02")
foreach ($dc in $DCs) {
    Invoke-Command -ComputerName $dc -ScriptBlock {
        Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
        Set-Service -Name Spooler -StartupType Disabled
    }
}

# Or via Group Policy (Domain Controllers OU):
# Computer Configuration → Policies → Windows Settings → Security Settings → System Services
# "Print Spooler" = Disabled
```

**Verification:**

```powershell
foreach ($dc in $DCs) {
    Get-Service -Name Spooler -ComputerName $dc | 
        Select-Object PSComputerName, Status, StartType
}
# Expected: Status = Stopped, StartType = Disabled
```

**Rollback:**

```powershell
foreach ($dc in $DCs) {
    Set-Service -Name Spooler -StartupType Manual -ComputerName $dc
    Start-Service -Name Spooler -ComputerName $dc
}
```

---

### H-05: RPC Coercion Vulnerability (Coercible Interfaces Exposed)

**Risk Description:**

Domain Controllers expose RPC interfaces that can be abused to force authentication:
- **PetitPotam (CVE-2021-36942):** Forces DC to authenticate to attacker system
- Combined with NTLM relay to ADCS, enables certificate-based attacks
- Can lead to complete domain compromise

**Business Impact:**
- Domain Controllers can be forced to authenticate to attacker-controlled systems
- NTLM relay to Certificate Authority enables attacker to obtain DC certificates
- Potential for complete domain takeover
- Critical infrastructure vulnerability

**Framework References:**
- CVE-2021-36942 (PetitPotam)
- MITRE ATT&CK: T1187 (Forced Authentication)
- Microsoft Security Advisory
- ISO 27001:2022 Control 8.8 (Technical Vulnerabilities)

**Detection:**

```powershell
# Check NTLM outbound restrictions on DCs (should block outbound NTLM)
foreach ($dc in $DCs) {
    Invoke-Command -ComputerName $dc -ScriptBlock {
        Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
            -Name "RestrictSendingNTLMTraffic" -ErrorAction SilentlyContinue
    }
}

# If not set or value < 2, DCs can send outbound NTLM (VULNERABLE)
```

**Audit First:**

```powershell
# Enable NTLM outbound auditing on DCs
foreach ($dc in $DCs) {
    Invoke-Command -ComputerName $dc -ScriptBlock {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
            -Name "RestrictSendingNTLMTraffic" -Value 1 -Type DWord
        # Value 1 = Audit, Value 2 = Block
    }
}

# Monitor for 48-72 hours
Get-WinEvent -FilterHashtable @{LogName='System';ID=4001} -MaxEvents 100
```

**Impact Assessment:**
- Monitor for legitimate NTLM outbound connections from DCs
- Typically NONE expected (DCs should not initiate NTLM authentication)
- 48-72 hour monitoring period
- Any outbound NTLM from DC is suspicious and warrants investigation

**Mitigation:**

```powershell
# Block NTLM outbound traffic from DCs
foreach ($dc in $DCs) {
    Invoke-Command -ComputerName $dc -ScriptBlock {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
            -Name "RestrictSendingNTLMTraffic" -Value 2 -Type DWord
    }
}

# Or via GPO on Domain Controllers OU:
# Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options
# "Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers" = "Deny all"
```

**Verification:**

```powershell
foreach ($dc in $DCs) {
    Invoke-Command -ComputerName $dc -ScriptBlock {
        Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
            -Name "RestrictSendingNTLMTraffic"
    }
}
# Expected: RestrictSendingNTLMTraffic = 2 (Block)
```

**Rollback:**

```powershell
foreach ($dc in $DCs) {
    Invoke-Command -ComputerName $dc -ScriptBlock {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
            -Name "RestrictSendingNTLMTraffic" -Value 0
    }
}
```

---

## 4.5 MEDIUM Risk Findings

This section summarizes the 8 MEDIUM-risk findings requiring remediation within 14-30 days. Full implementation details are provided in Chapters 5 and 6.

### Summary Table

Each finding follows the Detection → Audit → Mitigation → Verification pattern.

| Finding | Description | Detection Method | Key Remediation | Timeline |
|---------|-------------|------------------|-----------------|----------|
| **M-01** | DC Audit Baseline Missing | `auditpol /get /category:*` | Apply Advanced Audit Policy | 14-21 days |
| **M-02** | LDAPS Channel Binding Not Enforced | Check `LdapEnforceChannelBinding` registry | Enable channel binding (value 1 or 2) | 14-21 days |
| **M-03** | LDAP Signing Not Required | Check `LDAPServerIntegrity` registry | Require LDAP signing (value 2) | 14-21 days |
| **M-04** | ADCS Web Enrollment Uses HTTP | Check IIS bindings on CA | Remove HTTP binding, HTTPS only | 14-21 days |
| **M-05** | Missing AD Sites & Subnets | `Get-ADReplicationSite` | Configure AD Sites properly | 21-30 days |
| **M-06** | Admin Accounts Not Protected from Delegation | Check `AccountNotDelegated` flag | Set sensitive flag for admins | 21-30 days |
| **M-07** | Schema Admins Group Not Empty | `Get-ADGroupMember "Schema Admins"` | Empty privileged group (JIT access) | 21-30 days |
| **M-08** | UNC Hardened Paths Not Configured | Check GPO registry settings | Configure hardened UNC paths | 21-30 days |

### M-02 Example: LDAPS Channel Binding Not Enforced

**Detection:**

```powershell
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue
```

**Audit First:**

```powershell
# Enable LDAP diagnostics to monitor client connections
reg add "HKLM\System\CurrentControlSet\Services\NTDS\Diagnostics" `
    /v "16 LDAP Interface Events" /t REG_DWORD /d 2 /f

# Monitor Event Log for 48-72 hours
Get-WinEvent -FilterHashtable @{LogName='Directory Service';ID=2886,2887,2888,2889} -MaxEvents 100
```

**Mitigation:**

```powershell
# Set to value 1 (when supported) or 2 (always)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LdapEnforceChannelBinding" -Value 1
```

**Verification:**

```powershell
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LdapEnforceChannelBinding"
# Expected: LdapEnforceChannelBinding = 1 or 2
```

**Impact Assessment:** Monitor for authentication failures in audit mode before enforcing.

---

## 4.6 LOW Risk Findings

### L-01: AD Recycle Bin Not Enabled

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

## 4.7 Additional Security Hardening Opportunities

Beyond PingCastle findings, the following security enhancements were identified:

### Secure Remote Desktop Protocol (RDP)
- Enable Network Level Authentication (NLA)
- Set encryption to High
- Enable Restricted Admin Mode
- Implement firewall IP restrictions

### Secure Windows Remote Management (WinRM)
- Remove HTTP listeners (use HTTPS only)
- Certificate-based authentication
- Restrict TrustedHosts
- Enable WinRM auditing

### Group Managed Service Accounts (gMSA)
- Automatic password management for service accounts
- Eliminates manual service account password management
- Improved security over traditional service accounts

### LLMNR/NetBIOS Disablement
- Disable Link-Local Multicast Name Resolution
- Disable NetBIOS over TCP/IP
- Prevent name resolution poisoning attacks

### PowerShell Script Block Logging
- Enable PowerShell logging for security monitoring
- Capture potentially malicious script execution
- Integration with SIEM

### Protected Users Security Group
- Enhanced protection for privileged accounts
- Forces Kerberos authentication
- No NTLM, DES, or RC4 encryption
- Cannot be delegated

---

## 4.8 Framework Alignment Analysis

### ISO/IEC 27001:2022 Coverage

The hardening plan addresses the following ISO 27001:2022 controls:

| Control | Title | Findings Addressed |
|---------|-------|-------------------|
| 5.17 | Authentication information | H-01 (Password Policy), H-03 (LAPS) |
| 5.18 | Access rights | H-03 (LAPS), M-06 (Delegation), M-07 (Schema Admins) |
| 5.34 | Privacy and protection of PII | M-01 (Audit policies) |
| 8.2 | Privileged access rights | M-06, M-07 |
| 8.5 | Secure authentication | H-02 (NTLM), M-03 (LDAP signing) |
| 8.8 | Management of technical vulnerabilities | H-04 (Print Spooler), H-05 (RPC) |
| 8.13 | Information backup | L-01 (AD Recycle Bin) |
| 8.15 | Logging | M-01 (Audit baseline) |
| 8.24 | Use of cryptography | M-02 (LDAPS), M-04 (HTTPS) |

### MITRE ATT&CK Techniques

The hardening plan mitigates the following adversary techniques:

| Technique ID | Technique Name | Mitigations |
|--------------|----------------|-------------|
| T1078.003 | Valid Accounts: Local Accounts | LAPS deployment (H-03) |
| T1187 | Forced Authentication | Print Spooler disable (H-04), RPC restrictions (H-05) |
| T1201 | Password Policy Discovery | Strong password policy (H-01) |
| T1550.002 | Pass the Hash | NTLM restrictions (H-02) |
| T1557 | Adversary-in-the-Middle | LDAP signing (M-03), LDAPS binding (M-02) |
| T1557.001 | LLMNR/NBT-NS Poisoning | LLMNR/NetBIOS disable (future) |

### Compliance Impact

Implementation of the hardening plan supports compliance with:

- **NIST Cybersecurity Framework:** All five functions (Identify, Protect, Detect, Respond, Recover)
- **CIS Critical Security Controls:** Controls 4 (Secure Configuration), 5 (Account Management), 6 (Access Control)
- **PCI DSS:** Requirements 2 (Default passwords), 7 (Access control), 8 (Authentication), 10 (Logging)
- **GDPR:** Technical measures for data protection (Article 32)

---

## Summary

This chapter presented the security configuration assessment findings from PingCastle analysis of the contoso.com domain:

- **Overall Risk:** HIGH (Health Score: 77/100)
- **Total Findings:** 14 (5 HIGH, 8 MEDIUM, 1 LOW)
- **Critical Issues:** Weak passwords, NTLM vulnerabilities, missing LAPS, Print Spooler, RPC coercion
- **Framework Alignment:** ISO 27001:2022, MITRE ATT&CK, NIST, CIS

The next chapters detail the remediation implementation for insecure protocols (Chapter 5) and configuration hardening (Chapter 6).

---

[← Previous: Laboratory Environment](03-lab-environment.md) | [Next: Mitigating Insecure Protocols and Authentication →](05-protocol-remediation.md)

---

## Resources

- Microsoft security baseline guidance: https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines
- Guidance for securing Active Directory: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices
