[← Back to Main](../README.md)

# Appendix H: Complete VAPT Assessment Report

## Vulnerability Assessment and Penetration Testing  
### Active Directory Security Assessment - contoso.com Domain

**ISO/IEC 27001:2022 Aligned Report**

---

## Document Control

| Attribute | Details |
|-----------|---------|
| **Report Title** | VAPT - Active Directory Security Assessment |
| **Target Domain** | contoso.com |
| **Assessment Date** | 7 December 2025 |
| **Report Classification** | CONFIDENTIAL - Internal Use Only |
| **ISO/IEC Alignment** | ISO/IEC 27001:2022, ISO/IEC 27002:2022 |
| **Framework Mapping** | MITRE ATT&CK Enterprise Matrix |
| **Assessment Tool** | Netwrix PingCastle Basic Edition (Engine 3.4.1.38) |
| **Prepared By** | Ahmed Bayoumy, Senior Security Consultant |
| **Document Version** | 1.0 - Final |

---

## Executive Summary

### Overall Risk Assessment

The Active Directory security assessment of the **contoso.com** domain has identified a **HIGH** overall risk level with a **domain health score of 77 out of 100**. This assessment was conducted using automated discovery and rule-based checks through Netwrix PingCastle, followed by vulnerability analysis and penetration testing prioritization.

**Domain Health Scores:**

| Category | Score | Risk Level |
|----------|-------|------------|
| **Overall Risk** | 77/100 | HIGH |
| **Anomalies** | 77/100 | HIGH |
| **Stale Objects** | 31/100 | MEDIUM |
| **Privileged Accounts** | 40/100 | MEDIUM |

---

### Assessment Scope

The assessment covered:

- Active Directory domain **contoso.com** infrastructure
- Two Domain Controllers: **DC01** and **DC02** (Windows Server 2022)
- Group Policy Objects (GPOs) and their security configurations
- Public Key Infrastructure / Active Directory Certificate Services (**PKI/ADCS**)
- DNS configuration and security
- Privileged group memberships and delegation permissions

---

### Critical Findings Summary

The assessment identified **14 security vulnerabilities** requiring immediate attention. Five findings are classified as **HIGH risk** and pose immediate threats to domain security:

| Risk Level | Count | % of Total | ISO 27001 Controls | Priority |
|------------|-------|-----------|---------------------|----------|
| **HIGH** | 5 | 36% | 5.17, 5.18, 8.5 | Immediate |
| **MEDIUM** | 8 | 57% | 5.15, 8.2, 8.8 | 30 Days |
| **LOW** | 1 | 7% | 5.34 | 90 Days |

---

## Detailed Findings and Risk Assessment

This section provides comprehensive details of all identified vulnerabilities, organized by risk severity. Each finding includes ISO 27001:2022 control mapping, MITRE ATT&CK technique identification, and detailed remediation guidance.

---

## HIGH Risk Findings

### Finding H-01: Weak Password Policy (A-MinPwdLen)

| Attribute | Details |
|-----------|---------|
| **Risk Level** | HIGH |
| **ISO 27001:2022** | 5.17 (Authentication Information), 5.18 (Access Rights) |
| **MITRE ATT&CK** | T1201 - Password Policy Discovery |
| **PingCastle Rule** | A-MinPwdLen |

**Description:**

The Default Domain Policy permits a minimum password length of only **7 characters**, significantly below current security best practices and industry standards. This configuration increases susceptibility to brute force and dictionary attacks.

**Business Impact:**

Weak passwords can be compromised within hours using modern password cracking tools (hashcat, John the Ripper), potentially leading to:
- Unauthorized access to sensitive systems and data
- Data breaches and exfiltration
- Lateral movement across the network
- Complete domain compromise via privileged account takeover
- Regulatory compliance violations (GDPR, PCI DSS, HIPAA)
- Ransomware deployment

**Technical Details:**

```powershell
# Current Configuration (VULNERABLE)
Get-ADDefaultDomainPasswordPolicy

MinPasswordLength      : 7
PasswordHistoryCount   : 24
ComplexityEnabled      : True
MaxPasswordAge         : 42.00:00:00
MinPasswordAge         : 1.00:00:00
LockoutThreshold       : 0
```

**Exploitation Scenario:**

1. Attacker runs password spraying attack against AD accounts
2. Uses common 7-character passwords (e.g., "Winter2023!", "Summer2024!")
3. Successfully authenticates as multiple users with weak passwords
4. Uses compromised accounts to access file shares, emails, applications
5. Escalates privileges or moves laterally to compromise domain

**Remediation:**

**Detection:**
```powershell
Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength, PasswordHistoryCount, ComplexityEnabled
```

**Mitigation:**
```powershell
Set-ADDefaultDomainPasswordPolicy -Identity "contoso.com" `
    -MinPasswordLength 12 `
    -PasswordHistoryCount 24 `
    -ComplexityEnabled $true `
    -MaxPasswordAge (New-TimeSpan -Days 90) `
    -MinPasswordAge (New-TimeSpan -Days 1) `
    -LockoutThreshold 5 `
    -LockoutDuration (New-TimeSpan -Minutes 30) `
    -LockoutObservationWindow (New-TimeSpan -Minutes 30)
```

**Verification:**
```powershell
Get-ADDefaultDomainPasswordPolicy
# Expected: MinPasswordLength = 12
```

**Timeline:** Immediate (0-7 days)

---

### Finding H-02: NTLMv1/LM Authentication Enabled (S-OldNtlm)

| Attribute | Details |
|-----------|---------|
| **Risk Level** | HIGH |
| **ISO 27001:2022** | 8.5 (Secure Authentication) |
| **MITRE ATT&CK** | T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay |
| **PingCastle Rule** | S-OldNtlm |

**Description:**

Domain Controllers accept legacy **NTLMv1** and **LM** authentication protocols. These protocols use weak cryptographic algorithms vulnerable to relay attacks, hash cracking, and man-in-the-middle attacks. No Group Policy enforces secure LAN Manager authentication level.

**Business Impact:**

Attackers can:
- Capture and relay authentication traffic to gain unauthorized access to systems
- Crack NTLMv1 hashes offline using rainbow tables (minutes to hours)
- Perform NTLM relay attacks without cracking passwords
- This is a common initial access vector in ransomware and APT campaigns

**Technical Details:**

NTLMv1 uses DES encryption for challenge-response authentication, which is cryptographically broken. The LM hash algorithm is even weaker, supporting only uppercase letters and splitting passwords into 7-character chunks.

**Current Configuration:**
- LmCompatibilityLevel: Not configured (default = 3)
- Default allows NTLMv1 and LM authentication
- No NTLM auditing enabled

**Exploitation Scenario:**

1. Attacker performs LLMNR/NBT-NS poisoning (Responder tool)
2. Captures NTLMv1 authentication challenge-response
3. Cracks NTLMv1 hash offline (rainbow tables, GPU cracking)
4. OR: Relays NTLM authentication to another system (ntlmrelayx)
5. Gains unauthorized access without password knowledge

**Remediation:**

**Detection:**
```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
# If not set or < 5, NTLMv1 is allowed
```

**Audit First (CRITICAL):**
```powershell
# Enable NTLM auditing for 48-72 hours before enforcement
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
    -Name "AuditReceivingNTLMTraffic" -Value 2 -PropertyType DWord -Force

# Monitor Event ID 4624 for NTLM authentication
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 1000 | 
    Where-Object {$_.Message -like "*NTLM*"}
```

**Mitigation:**
```powershell
# Set LM Authentication Level to 5 (NTLMv2 only, refuse LM & NTLM)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LmCompatibilityLevel" -Value 5 -Type DWord

# Via GPO:
# Computer Configuration → Security Settings → Local Policies → Security Options
# Network security: LAN Manager authentication level = "Send NTLMv2 response only. Refuse LM & NTLM"
```

**Verification:**
```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel"
# Expected: LmCompatibilityLevel = 5
```

**Timeline:** Immediate (0-7 days, after 48-72 hour audit period)

---

### Finding H-03: LAPS Not Deployed (A-LAPS-Not-Installed)

| Attribute | Details |
|-----------|---------|
| **Risk Level** | HIGH |
| **ISO 27001:2022** | 5.17 (Authentication Information), 5.18 (Access Rights) |
| **MITRE ATT&CK** | T1078.003 - Valid Accounts: Local Accounts |
| **PingCastle Rule** | A-LAPS-Not-Installed |

**Description:**

Microsoft Local Administrator Password Solution (**LAPS**) is not deployed. Without LAPS, local administrator passwords are typically identical across workstations or remain unchanged for extended periods, enabling lateral movement.

**Business Impact:**

Compromising a single workstation's local admin account can enable:
- **Pass-the-Hash attacks** to access multiple systems
- Rapid lateral movement across all workstations
- Potential full domain compromise via privilege escalation
- Persistence via local administrator accounts

**Technical Details:**

Windows Server 2022 includes native **Windows LAPS** (built-in). No schema updates required. Passwords are 240 characters, randomly generated, and automatically rotated every 30 days.

**Current State:**
```powershell
# Check if LAPS passwords exist
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | 
    Where-Object {$_.'ms-Mcs-AdmPwd' -ne $null}

# Result: 0 computers (LAPS not deployed)
```

**Exploitation Scenario:**

1. Attacker compromises single workstation (phishing, malware)
2. Dumps local administrator password hash (same on all workstations)
3. Uses Pass-the-Hash to authenticate to other workstations
4. Spreads laterally across organization
5. Compromises privileged account or critical server

**Remediation:**

**Detection:**
```powershell
# Check if Windows LAPS is configured
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | 
    Where-Object {$_.'ms-Mcs-AdmPwd' -ne $null} | Measure-Object

# Count should be 0 if not deployed
```

**Audit First:**
```powershell
# Pilot deployment on test OU
New-ADOrganizationalUnit -Name "LAPS-Pilot" -Path "DC=contoso,DC=com"
# Move 2-3 test computers to pilot OU
# Monitor for 7 days
```

**Mitigation:**

Configure Windows LAPS via GPO:

**Computer Configuration → Administrative Templates → System → LAPS**

Settings:
- **Enable password backup directory:** Active Directory
- **Password Complexity:** 4 (Large, small, numbers, specials)
- **Password Length:** 14 characters
- **Password Age (Days):** 30 days
- **Administrator Account Name:** Administrator

**Verification:**
```powershell
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime | 
    Where-Object {$_.'ms-Mcs-AdmPwd' -ne $null} | 
    Select-Object Name, @{N='PasswordExpiry';E={[datetime]::FromFileTime($_.'ms-Mcs-AdmPwdExpirationTime')}}

# All workstations should have LAPS passwords
```

**Timeline:** Immediate (0-14 days)

---

### Finding H-04: Print Spooler Active on DCs (A-DC-Spooler)

| Attribute | Details |
|-----------|---------|
| **Risk Level** | HIGH |
| **CVE References** | CVE-2021-34527 (PrintNightmare), CVE-2021-1675 |
| **MITRE ATT&CK** | T1187 - Forced Authentication |
| **PingCastle Rule** | A-DC-Spooler |

**Description:**

Print Spooler service is **enabled and remotely accessible** on both DC01 and DC02. Domain Controllers rarely require printing capabilities and this service has been exploited in multiple high-profile vulnerabilities (**PrintNightmare**).

**Business Impact:**

Exploitation can lead to:
- **Remote code execution** with SYSTEM privileges on Domain Controllers
- Immediate and complete domain compromise
- Credential theft (NTDS.dit extraction)
- Ransomware deployment across entire domain
- Data exfiltration

**Technical Details:**

PrintNightmare (CVE-2021-34527) allows remote code execution via Print Spooler service. Even with patches applied, Print Spooler remains an unnecessary attack surface on Domain Controllers.

**Current State:**
```powershell
Get-Service -Name Spooler -ComputerName DC01,DC02

# Result:
# DC01: Running, Automatic
# DC02: Running, Automatic
```

**Exploitation Scenario:**

1. Attacker identifies Print Spooler running on DC (port 445/tcp)
2. Exploits PrintNightmare vulnerability (CVE-2021-34527)
3. Achieves remote code execution as SYSTEM on DC
4. Dumps NTDS.dit (all domain password hashes)
5. Creates Golden Ticket for persistence
6. Full domain compromise

**Remediation:**

**Detection:**
```powershell
Get-Service -Name Spooler -ComputerName DC01,DC02 | 
    Select-Object Name, Status, StartType
```

**Audit First:**
```powershell
# Verify no printers or print jobs on DCs
Get-Printer -ComputerName DC01,DC02
Get-PrintJob -ComputerName DC01,DC02
# Expected: No results
```

**Mitigation:**
```powershell
$DCs = @("DC01","DC02")
foreach($dc in $DCs){
    Invoke-Command -ComputerName $dc -ScriptBlock {
        Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
        Set-Service -Name Spooler -StartupType Disabled
    }
}

# Via GPO:
# Computer Configuration → System Services → Print Spooler = Disabled
```

**Verification:**
```powershell
Get-Service -Name Spooler -ComputerName DC01,DC02 | 
    Select-Object Name, Status, StartType

# Expected: Status=Stopped, StartType=Disabled
```

**Timeline:** Immediate (0-7 days)

---

### Finding H-05: RPC Coercion Vulnerability (A-DC-Coerce)

| Attribute | Details |
|-----------|---------|
| **Risk Level** | HIGH |
| **CVE References** | CVE-2021-36942 (PetitPotam) |
| **MITRE ATT&CK** | T1187 - Forced Authentication |
| **PingCastle Rule** | A-DC-Coerce |

**Description:**

**DC02** (192.168.51.12) exposes coercible RPC interfaces that can force authentication. PingCastle identified accessible printer notification interfaces (UUID `12345678-1234-abcd-ef00-0123456789ab`, OpNum 62/65). These can be exploited to coerce NTLM authentication from the DC.

**Business Impact:**

Combined with ADCS misconfigurations, this enables:
- Complete domain takeover via **ESC8** attack (NTLM relay to ADCS)
- Attacker can relay DC authentication to compromise PKI infrastructure
- Issue arbitrary certificates (including Domain Controller certificates)
- Authenticate as Domain Controller (DCSync, Golden Ticket)
- Full domain compromise

**Technical Details:**

**PetitPotam** (CVE-2021-36942) exploits MS-EFSRPC (Encrypting File System Remote Protocol) to coerce NTLM authentication from Domain Controllers. Even with patches applied, other RPC interfaces may still allow coercion.

**Exploitation Scenario:**

1. Attacker runs PetitPotam tool targeting DC02
2. Coerced authentication forces DC02 to connect to attacker-controlled system
3. DC sends NTLM authentication
4. Attacker relays DC authentication to Certificate Authority web enrollment
5. Requests Domain Controller certificate
6. Uses certificate to authenticate as DC02
7. Performs DCSync attack (replicates all password hashes)
8. Full domain compromise

**Remediation:**

**Detection:**
```powershell
# Check NTLM outbound restrictions on DCs
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RestrictSendingNTLMTraffic" -ErrorAction SilentlyContinue
```

**Audit First:**
```powershell
# Enable NTLM outbound auditing on DCs (Value 1 = Audit)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
    -Name "RestrictSendingNTLMTraffic" -Value 1 -Type DWord

# Monitor for 48-72 hours
Get-WinEvent -FilterHashtable @{LogName='System';ID=4001} -MaxEvents 100
```

**Mitigation:**
```powershell
# Block NTLM outbound traffic from DCs (Value 2 = Block)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
    -Name "RestrictSendingNTLMTraffic" -Value 2 -Type DWord

# Via GPO on Domain Controllers OU:
# Computer Config → Security Settings → Local Policies → Security Options
# Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers = Deny all
```

**Verification:**
```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
    -Name "RestrictSendingNTLMTraffic"

# Expected: 2 (Block)
```

**Additional Mitigations:**
- Apply KB5005413 (PetitPotam patch)
- Disable NTLM authentication on ADCS web enrollment
- Enable Extended Protection for Authentication (EPA) on ADCS

**Timeline:** Immediate (0-14 days)

---

## MEDIUM Risk Findings (Summary)

Eight medium-risk findings require remediation within 30 days:

| Finding ID | Description | ISO Control | Key Remediation |
|------------|-------------|-------------|-----------------|
| **M-01** | DC Audit Baseline Missing | 8.15 | Apply Advanced Audit Policy for DCs |
| **M-02** | LDAPS Channel Binding Not Enforced | 8.5 | Enable LdapEnforceChannelBinding registry |
| **M-03** | LDAP Signing Not Required | 8.5 | Require LDAP signing via GPO |
| **M-04** | ADCS Web Enrollment HTTP | 8.24 | Remove HTTP binding; enforce HTTPS |
| **M-05** | Missing AD Sites & Subnets | 8.2 | Declare missing subnets for DC IPs |
| **M-06** | Admin Accounts Not Protected | 5.18 | Set sensitive flag or Protected Users |
| **M-07** | Schema Admins Not Empty | 5.18 | Empty Schema Admins group |
| **M-08** | UNC Hardened Paths Missing | 8.5 | Configure Hardened UNC paths GPO |

---

### Finding M-01: DC Audit Baseline Missing

**Risk Level:** MEDIUM  
**ISO 27001:2022:** 8.15 (Logging)  
**Remediation:** Apply Advanced Audit Policy for comprehensive event logging

Configure Advanced Audit Policy via GPO:
- Credential Validation: Success and Failure
- Kerberos Authentication Service: Success and Failure
- User Account Management: Success and Failure
- Security Group Management: Success and Failure
- Directory Service Changes: Success and Failure

---

### Finding M-02: LDAPS Channel Binding Not Enforced

**Risk Level:** MEDIUM  
**ISO 27001:2022:** 8.5 (Secure Authentication), 8.24 (Use of Cryptography)  
**Remediation:** Enable LDAPS channel binding

```powershell
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LdapEnforceChannelBinding" -Value 1
```

---

### Finding M-03: LDAP Signing Not Required

**Risk Level:** MEDIUM  
**ISO 27001:2022:** 8.5 (Secure Authentication)  
**Remediation:** Require LDAP signing

```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LDAPServerIntegrity" -Value 2
```

---

### Finding M-04: ADCS Web Enrollment Uses HTTP

**Risk Level:** MEDIUM  
**ISO 27001:2022:** 8.24 (Use of Cryptography)  
**Remediation:** Remove HTTP binding, enforce HTTPS only

```powershell
Remove-WebBinding -Name "Default Web Site" -Protocol "http" -Port 80
```

---

### Finding M-05: Missing AD Sites & Subnets

**Risk Level:** MEDIUM  
**ISO 27001:2022:** 8.2 (Privileged Access Rights)  
**Remediation:** Declare subnet 192.168.51.0/24

```powershell
New-ADReplicationSubnet -Name "192.168.51.0/24" -Site "Default-First-Site-Name"
```

---

### Finding M-06: Admin Accounts Not Protected from Delegation

**Risk Level:** MEDIUM  
**ISO 27001:2022:** 5.18 (Access Rights)  
**Remediation:** Set "sensitive and cannot be delegated" flag

```powershell
Get-ADUser -Filter {AdminCount -eq 1} | 
    Set-ADAccountControl -AccountNotDelegated $true
```

---

### Finding M-07: Schema Admins Group Not Empty

**Risk Level:** MEDIUM  
**ISO 27001:2022:** 5.18 (Access Rights)  
**Remediation:** Empty Schema Admins group

```powershell
Get-ADGroupMember "Schema Admins" | ForEach-Object {
    Remove-ADGroupMember "Schema Admins" -Members $_ -Confirm:$false
}
```

---

### Finding M-08: UNC Hardened Paths Not Configured

**Risk Level:** MEDIUM  
**ISO 27001:2022:** 8.5 (Secure Authentication)  
**Remediation:** Configure UNC hardened paths via GPO

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" `
    -Name "\\*\SYSVOL" -Value "RequireMutualAuthentication=1,RequireIntegrity=1"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" `
    -Name "\\*\NETLOGON" -Value "RequireMutualAuthentication=1,RequireIntegrity=1"
```

---

## LOW Risk Findings

### Finding L-01: AD Recycle Bin Not Enabled

**Risk Level:** LOW  
**ISO 27001:2022:** 5.34 (Privacy and Protection of PII)  
**Impact:** Limited recovery options for deleted AD objects

**Remediation:**
```powershell
Enable-ADOptionalFeature -Identity "Recycle Bin Feature" `
    -Scope ForestOrConfigurationSet -Target "contoso.com" -Confirm:$false
```

**Timeline:** 90 days

---

## Remediation Roadmap

### Prioritized Implementation Plan

The following phased approach balances security impact with operational stability:

---

#### Phase 1: Immediate Actions (0-7 Days)

**Objective:** Address critical vulnerabilities that could lead to domain compromise

1. **Disable Print Spooler on DC01 and DC02**
   - Minimal impact. Can be executed immediately without compatibility testing.

2. **Ban NTLMv1/LM Authentication**
   - Test in audit mode for 48 hours to identify legacy dependencies before enforcement.

3. **Strengthen Password Policy**
   - Communicate changes to users 48 hours in advance. Minimal operational impact.

**Deliverables:**
- Print Spooler disabled on all DCs
- Password policy updated to 12-character minimum
- NTLM audit data collected for Phase 2 enforcement

---

#### Phase 2: High Priority (7-14 Days)

**Objective:** Deploy critical security controls and enforce authentication hardening

1. **Deploy Microsoft LAPS**
   - Pilot with IT workstations first, then roll out domain-wide. Coordinate with helpdesk.

2. **Mitigate RPC Coercion Attacks**
   - Apply NTLM restrictions in Audit mode first to identify impact, then enforce blocking.

**Deliverables:**
- NTLMv1 fully banned domain-wide
- LAPS successfully piloted on test systems
- RPC coercion attacks mitigated via NTLM restrictions

---

#### Phase 3: Medium Priority (14-30 Days)

**Objective:** Implement protocol security and comprehensive audit controls

1. **LDAP Security Hardening**
   - Enable LDAP signing and channel binding. Test compatibility with applications.

2. **Apply DC Audit Baseline**
   - Configure advanced audit policies. Ensure SIEM capacity for log volume increase.

3. **Secure ADCS Web Enrollment**
   - Remove HTTP binding and enforce HTTPS only on CA01.

4. **Complete AD Sites & Services Configuration**
   - Add missing subnet declarations for optimal DC selection and replication.

5. **Protect Privileged Accounts from Delegation**
   - Enable delegation protection and add to Protected Users group where feasible.

**Deliverables:**
- LDAP signing and channel binding enforced
- Advanced audit policy active on all DCs
- ADCS web enrollment secured (HTTPS only)
- AD Sites properly configured
- Privileged accounts hardened

---

#### Phase 4: Additional Hardening (30-90 Days)

**Objective:** Deploy advanced security features and complete defense-in-depth strategy

1. Enable AD Recycle Bin
2. Empty Schema Admins group
3. Configure UNC Hardened Paths
4. Implement gMSA for service accounts
5. Disable LLMNR via GPO
6. Enable PowerShell logging

---

## ISO 27001:2022 Control Mapping

The following table maps identified findings to ISO/IEC 27001:2022 controls, demonstrating comprehensive coverage of information security management requirements:

| ISO 27001 Control | Control Name | Affected Findings |
|-------------------|--------------|-------------------|
| **5.17** | Authentication Information | H-01 (Password Policy), H-03 (LAPS) |
| **5.18** | Access Rights | M-06 (Delegation), M-07 (Schema Admins) |
| **5.34** | Privacy & PII Protection | L-01 (AD Recycle Bin) |
| **8.2** | Privileged Access Rights | M-05 (AD Sites Configuration) |
| **8.5** | Secure Authentication | H-02 (NTLMv1), M-02 (Channel Binding), M-03 (LDAP Signing), M-08 (UNC Paths) |
| **8.8** | Management of Technical Vulnerabilities | H-04 (Print Spooler), H-05 (RPC Coercion) |
| **8.15** | Logging | M-01 (DC Audit Baseline) |
| **8.24** | Use of Cryptography | M-04 (ADCS HTTPS) |

---

## MITRE ATT&CK Technique Coverage

The assessment identified vulnerabilities corresponding to the following MITRE ATT&CK Enterprise techniques:

| Technique ID | Technique Name | Affected Findings |
|--------------|----------------|-------------------|
| **T1078.003** | Valid Accounts: Local Accounts | H-03 (LAPS Not Deployed) |
| **T1187** | Forced Authentication | H-04 (Print Spooler), H-05 (RPC Coercion) |
| **T1201** | Password Policy Discovery | H-01 (Weak Password Policy) |
| **T1557** | Adversary-in-the-Middle | M-02 (Channel Binding), M-03 (LDAP Signing), M-04 (ADCS HTTP) |
| **T1557.001** | LLMNR/NBT-NS Poisoning | H-02 (NTLMv1), M-08 (UNC Paths) |

---

## Conclusion and Recommendations

### Risk Summary

The **contoso.com** Active Directory domain exhibits a **HIGH overall security risk (77/100)** with critical vulnerabilities that require immediate remediation. The assessment identified **14 findings** across authentication, authorization, cryptography, and system hardening controls mapped to ISO/IEC 27001:2022 and MITRE ATT&CK framework.

---

### Priority Actions

The following actions should be prioritized for immediate implementation:

1. Disable Print Spooler service on all Domain Controllers (0-7 days)
2. Ban NTLMv1/LM authentication protocols domain-wide (0-7 days)
3. Increase minimum password length to 12 characters (0-7 days)
4. Deploy Microsoft LAPS for local administrator password management (7-14 days)
5. Implement NTLM restrictions to mitigate RPC coercion attacks (7-14 days)

---

### Implementation Strategy

Remediation should follow a staged rollout approach:

- Test all changes in a pilot OU before domain-wide deployment
- Use Audit mode for potentially disruptive controls (NTLM restrictions, LDAP signing) before enforcement
- Communicate changes to IT staff and end users with appropriate lead time
- Monitor authentication and application logs during the 48-hour audit period
- Establish rollback procedures for each change
- Document all configuration changes in change management system

---

### Ongoing Security Measures

Beyond immediate remediation, implement the following security practices:

- Conduct quarterly Active Directory security assessments using PingCastle or similar tools
- Enable and monitor Advanced Audit Policy events in SIEM
- Implement privileged access workstations (PAWs) for administrative tasks
- Establish regular review cycles for privileged group memberships
- Deploy EDR solutions with Active Directory attack detection capabilities
- Conduct annual penetration testing of Active Directory infrastructure
- Maintain current patch levels on all Domain Controllers and member servers

---

### Compliance Alignment

Implementation of the recommended remediations will significantly improve alignment with:

- ISO/IEC 27001:2022 controls 5.17, 5.18, 8.2, 8.5, 8.8, 8.15, and 8.24
- NIST Cybersecurity Framework (CSF) Protect and Detect functions
- CIS Critical Security Controls for Active Directory
- MITRE ATT&CK mitigation strategies for credential access and lateral movement
- PCI DSS requirements for authentication and access control (if applicable)
- GDPR technical and organizational measures for data protection

---

## Assessment Methodology

This assessment was conducted using a combination of automated scanning and manual analysis:

- Automated domain health check using **Netwrix PingCastle Basic Edition 3.4.1.38**
- Rule-based vulnerability detection against CIS benchmarks and Microsoft security baselines
- Configuration analysis of Group Policy Objects, DNS, PKI/ADCS, and Active Directory Sites
- Privileged group membership enumeration and delegation permission review
- MITRE ATT&CK technique mapping for identified vulnerabilities
- ISO/IEC 27001:2022 control alignment analysis

---

## Risk Rating Criteria

| Risk Level | Criteria | Remediation Timeline |
|------------|----------|---------------------|
| **HIGH** | Can lead to immediate domain compromise, credential theft, or lateral movement. Commonly exploited by ransomware and APT groups. | Immediate (0-14 days) |
| **MEDIUM** | Weakens security posture and can be chained with other vulnerabilities. May enable reconnaissance or privilege escalation. | 30 days |
| **LOW** | Represents security best practice gaps with minimal immediate risk. Improves defense-in-depth strategy. | 90 days |

---

## Reference Documentation

- Microsoft Security Baselines for Windows Server 2022
- CIS Benchmark for Microsoft Windows Server 2022
- NIST SP 800-53 Rev. 5 Security Controls
- ISO/IEC 27001:2022 Information Security Management
- ISO/IEC 27002:2022 Information Security Controls
- MITRE ATT&CK Enterprise Matrix v15
- Netwrix PingCastle Documentation and Rule Descriptions
- Microsoft Active Directory Security Best Practices
- ANSSI Active Directory Security Recommendations

---

## Contact Information

**Report Prepared By:** Ahmed Bayoumy  
**Title:** Senior Security Consultant  
**Assessment Date:** 7 December 2025  
**Document Version:** 1.0 - Final

---

[← Back to Main](../README.md)
