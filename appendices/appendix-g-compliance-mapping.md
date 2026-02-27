[← Back to Main](../README.md)

# Appendix G: Compliance Framework Mapping

## ISO 27001:2022 and MITRE ATT&CK Alignment

This appendix provides comprehensive mapping of security findings to ISO/IEC 27001:2022 controls and MITRE ATT&CK Enterprise Matrix techniques.

---

## Table of Contents

1. [ISO 27001:2022 Control Mapping](#iso-270012022-control-mapping)
2. [MITRE ATT&CK Technique Coverage](#mitre-attck-technique-coverage)
3. [Cross-Framework Alignment](#cross-framework-alignment)
4. [Compliance Gap Analysis](#compliance-gap-analysis)

---

## ISO 27001:2022 Control Mapping

### Complete Finding-to-Control Matrix

| Finding ID | Finding Description | ISO 27001:2022 Controls | Annex A Reference |
|------------|---------------------|------------------------|-------------------|
| **H-01** | Weak Password Policy (7 characters) | 5.17, 5.18 | A.5.17 Authentication information<br>A.5.18 Access rights |
| **H-02** | NTLMv1/LM Authentication Enabled | 8.5 | A.8.5 Secure authentication |
| **H-03** | LAPS Not Deployed | 5.17, 5.18 | A.5.17 Authentication information<br>A.5.18 Access rights |
| **H-04** | Print Spooler Active on DCs | 8.8 | A.8.8 Management of technical vulnerabilities |
| **H-05** | RPC Coercion Vulnerability | 8.8 | A.8.8 Management of technical vulnerabilities |
| **M-01** | DC Audit Baseline Missing | 8.15 | A.8.15 Logging |
| **M-02** | LDAPS Channel Binding Not Enforced | 8.5, 8.24 | A.8.5 Secure authentication<br>A.8.24 Use of cryptography |
| **M-03** | LDAP Signing Not Required | 8.5 | A.8.5 Secure authentication |
| **M-04** | ADCS Web Enrollment Uses HTTP | 8.24 | A.8.24 Use of cryptography |
| **M-05** | Missing AD Sites & Subnets | 8.2 | A.8.2 Privileged access rights |
| **M-06** | Admin Accounts Not Protected from Delegation | 5.18 | A.5.18 Access rights |
| **M-07** | Schema Admins Group Not Empty | 5.18 | A.5.18 Access rights |
| **M-08** | UNC Hardened Paths Not Configured | 8.5 | A.8.5 Secure authentication |
| **L-01** | AD Recycle Bin Not Enabled | 5.34 | A.5.34 Privacy and protection of PII |

---

### ISO 27001:2022 Controls Detailed Mapping

#### Control 5.17: Authentication Information

**Objective:** To ensure the proper allocation, management, and security of authentication information.

**Findings Addressed:**
- **H-01:** Weak Password Policy (7 characters)
- **H-03:** LAPS Not Deployed

**Implementation Guidance:**
```
Remediation Actions:
1. Increase minimum password length to 12 characters
2. Enable password complexity requirements
3. Set password history to 24 passwords
4. Deploy LAPS for local administrator password management
5. Implement gMSA for service accounts

Verification:
- Get-ADDefaultDomainPasswordPolicy confirms 12-character minimum
- Get-ADComputer shows LAPS passwords managed for all workstations
- Passwords automatically rotated every 30 days (LAPS)
```

**Evidence of Compliance:**
- Password policy GPO export showing minimum 12 characters
- LAPS deployment verification script results
- Password rotation audit logs

---

#### Control 5.18: Access Rights

**Objective:** To ensure access rights are allocated and managed in accordance with business and security requirements.

**Findings Addressed:**
- **H-01:** Weak Password Policy
- **H-03:** LAPS Not Deployed
- **M-06:** Admin Accounts Not Protected from Delegation
- **M-07:** Schema Admins Group Not Empty

**Implementation Guidance:**
```
Remediation Actions:
1. Set "Account is sensitive and cannot be delegated" flag on admin accounts
2. Add eligible admin accounts to Protected Users security group
3. Empty Schema Admins group (just-in-time access model)
4. Implement privileged access management (PAM) processes

Verification:
- Get-ADUser -Filter {AdminCount -eq 1} shows AccountNotDelegated = True
- Get-ADGroupMember "Schema Admins" returns no members
- Get-ADGroupMember "Protected Users" shows critical admin accounts
```

**Evidence of Compliance:**
- Active Directory user attribute reports
- Privileged group membership audit logs
- Just-in-time access request logs

---

#### Control 5.34: Privacy and Protection of PII

**Objective:** To ensure compliance with legal, regulatory, and contractual obligations related to privacy and PII.

**Findings Addressed:**
- **L-01:** AD Recycle Bin Not Enabled

**Implementation Guidance:**
```
Remediation Actions:
1. Verify forest functional level (Windows Server 2008 R2 or higher)
2. Enable AD Recycle Bin (irreversible operation):
   Enable-ADOptionalFeature -Identity "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target "contoso.com"
3. Document recovery procedures using AD Recycle Bin
4. Train administrators on AD object recovery

Verification:
- (Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"').EnabledScopes returns forest DN
```

**Evidence of Compliance:**
- AD Recycle Bin enablement confirmation
- Recovery procedure documentation
- Administrator training records

---

#### Control 8.2: Privileged Access Rights

**Objective:** To restrict and control the allocation and use of privileged access rights.

**Findings Addressed:**
- **M-05:** Missing AD Sites & Subnets

**Implementation Guidance:**
```
Remediation Actions:
1. Declare missing subnet 192.168.51.0/24 in AD Sites and Services
2. Associate subnet with Default-First-Site-Name
3. Verify DC site assignment
4. Optimize replication topology

Verification:
- Get-ADReplicationSubnet -Filter * shows subnet 192.168.51.0/24
- Get-ADReplicationSite shows site configuration
- Get-ADDomainController shows correct site assignment
```

**Evidence of Compliance:**
- AD Sites and Services configuration export
- Replication topology diagram
- Site assignment verification report

---

#### Control 8.5: Secure Authentication

**Objective:** To implement secure, fit-for-purpose authentication technologies and procedures.

**Findings Addressed:**
- **H-02:** NTLMv1/LM Authentication Enabled
- **M-02:** LDAPS Channel Binding Not Enforced
- **M-03:** LDAP Signing Not Required
- **M-08:** UNC Hardened Paths Not Configured

**Implementation Guidance:**
```
Remediation Actions:
1. Set LM Authentication Level to 5 (NTLMv2 only, refuse LM & NTLM)
   Registry: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel = 5

2. Require LDAP signing:
   Registry: HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity = 2

3. Enable LDAPS channel binding:
   Registry: HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding = 1

4. Configure UNC hardened paths:
   Registry: HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths
   \\*\SYSVOL = RequireMutualAuthentication=1,RequireIntegrity=1
   \\*\NETLOGON = RequireMutualAuthentication=1,RequireIntegrity=1

Verification:
- Registry values match expected secure configuration
- LDAP diagnostics show no unsigned binds
- Authentication failures absent in event logs
```

**Evidence of Compliance:**
- Registry configuration exports
- LDAP diagnostic event logs (Event ID 2889)
- Authentication audit logs

---

#### Control 8.8: Management of Technical Vulnerabilities

**Objective:** To prevent exploitation of technical vulnerabilities.

**Findings Addressed:**
- **H-04:** Print Spooler Active on DCs (CVE-2021-34527)
- **H-05:** RPC Coercion Vulnerability (CVE-2021-36942)

**Implementation Guidance:**
```
Remediation Actions:
1. Disable Print Spooler on all Domain Controllers:
   Stop-Service Spooler; Set-Service Spooler -StartupType Disabled

2. Block NTLM outbound traffic from DCs (RPC coercion mitigation):
   Registry: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic = 2

3. Apply security patches:
   - KB5005010 (PrintNightmare patch)
   - KB5005413 (PetitPotam mitigations)

4. Monitor for exploitation attempts:
   - Event ID 4624 (failed NTLM authentication from DCs)
   - Event ID 808 (Print Spooler access attempts)

Verification:
- Get-Service Spooler shows Status=Stopped, StartType=Disabled
- Registry shows RestrictSendingNTLMTraffic = 2
- Patch compliance report shows KB5005010, KB5005413 installed
```

**Evidence of Compliance:**
- Service status verification reports
- Patch compliance reports
- Security event monitoring logs

---

#### Control 8.15: Logging

**Objective:** To record events and generate evidence.

**Findings Addressed:**
- **M-01:** DC Audit Baseline Missing

**Implementation Guidance:**
```
Remediation Actions:
1. Apply Advanced Audit Policy via GPO or auditpol commands:
   - Credential Validation: Success and Failure
   - Kerberos Authentication Service: Success and Failure
   - User Account Management: Success and Failure
   - Security Group Management: Success and Failure
   - Directory Service Changes: Success and Failure
   - Account Lockout: Failure
   - Logon: Success and Failure
   - Special Logon: Success and Failure
   - Audit Policy Change: Success and Failure
   - Sensitive Privilege Use: Success and Failure

2. Configure log retention:
   - Security log size: 4 GB minimum
   - Retention method: Overwrite events as needed
   - SIEM forwarding: Configure for all DCs

3. Enable PowerShell logging:
   - Script Block Logging: Enabled
   - Module Logging: Enabled
   - Transcription: Enabled (optional)

Verification:
- auditpol /get /category:* shows all required subcategories enabled
- Get-EventLog Security -Newest 10 shows audit events being logged
- SIEM dashboard shows DC logs being ingested
```

**Evidence of Compliance:**
- Audit policy configuration export
- Event log samples
- SIEM ingestion confirmation reports

---

#### Control 8.24: Use of Cryptography

**Objective:** To ensure proper and effective use of cryptography to protect information confidentiality, authenticity, and integrity.

**Findings Addressed:**
- **M-02:** LDAPS Channel Binding Not Enforced
- **M-04:** ADCS Web Enrollment Uses HTTP

**Implementation Guidance:**
```
Remediation Actions:
1. Enable LDAPS channel binding:
   Registry: HKLM\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding = 1

2. Remove HTTP binding from ADCS web enrollment:
   Remove-WebBinding -Name "Default Web Site" -Protocol "http" -Port 80

3. Enforce HTTPS-only access to certificate enrollment:
   - Configure IIS to require SSL
   - Redirect HTTP to HTTPS (optional)
   - Deploy server authentication certificate to CA

4. Disable weak cryptographic protocols:
   - TLS 1.0: Disabled
   - TLS 1.1: Disabled
   - TLS 1.2: Enabled
   - TLS 1.3: Enabled

Verification:
- Test-WSMan -ComputerName DC01 -UseSSL succeeds
- https://ca01.contoso.com/certsrv accessible
- http://ca01.contoso.com/certsrv returns error or redirects
- Get-TlsCipherSuite shows only strong ciphers enabled
```

**Evidence of Compliance:**
- IIS binding configuration exports
- SSL/TLS cipher suite reports
- Certificate deployment verification

---

## MITRE ATT&CK Technique Coverage

### ATT&CK Matrix Mapping

| Technique ID | Technique Name | Tactic | Affected Findings | Mitigation |
|--------------|----------------|--------|-------------------|------------|
| **T1078.003** | Valid Accounts: Local Accounts | Initial Access, Persistence | H-03 (LAPS Not Deployed) | Deploy LAPS, rotate passwords every 30 days |
| **T1187** | Forced Authentication | Credential Access | H-04 (Print Spooler), H-05 (RPC Coercion) | Disable Print Spooler, block NTLM outbound |
| **T1201** | Password Policy Discovery | Discovery | H-01 (Weak Password Policy) | Increase minimum password length to 12 characters |
| **T1557** | Adversary-in-the-Middle | Collection, Credential Access | M-02, M-03, M-04 | Enforce LDAP signing, LDAPS channel binding, HTTPS |
| **T1557.001** | LLMNR/NBT-NS Poisoning and SMB Relay | Credential Access | H-02 (NTLMv1), M-08 (UNC Paths) | Ban NTLMv1, configure UNC hardened paths |

---

### Technique T1078.003: Valid Accounts: Local Accounts

**Description:** Adversaries may obtain and abuse credentials of local accounts to gain Initial Access, Persistence, Privilege Escalation, or Defense Evasion.

**Finding:** H-03 - LAPS Not Deployed

**Attack Scenario:**
```
1. Attacker compromises single workstation (phishing, drive-by download, etc.)
2. Dumps local administrator password hash (static password "Password123")
3. Uses Pass-the-Hash attack to authenticate to other workstations with same local admin password
4. Lateral movement across all workstations in domain
5. Eventually compromises privileged account or server
```

**Mitigation:**
- Deploy Windows LAPS to manage local administrator passwords
- Randomize passwords (14 characters, complexity level 4)
- Automatic rotation every 30 days
- Store passwords in Active Directory (ms-Mcs-AdmPwd attribute)
- Delegate password retrieval to authorized administrators only

**Verification:**
```powershell
# Check LAPS deployment
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | 
    Where-Object {$_.'ms-Mcs-AdmPwd' -ne $null} | 
    Measure-Object | Select-Object -ExpandProperty Count

# Expected: 100% of workstations managed by LAPS
```

---

### Technique T1187: Forced Authentication

**Description:** Adversaries may coerce a system to authenticate to a system they control, enabling credential theft via relay or hash capture.

**Findings:** 
- H-04 - Print Spooler Active on DCs (PrintNightmare / SpoolSample)
- H-05 - RPC Coercion Vulnerability (PetitPotam)

**Attack Scenario:**
```
1. Attacker runs PetitPotam or SpoolSample tool targeting DC
2. Coerced authentication forces DC to connect to attacker-controlled system
3. DC sends NTLM authentication (can be relayed to ADCS)
4. Attacker relays DC authentication to Certificate Authority web enrollment
5. Requests Domain Controller certificate
6. Uses certificate to authenticate as DC (DCSync, Golden Ticket, etc.)
7. Full domain compromise
```

**Mitigation:**
- Disable Print Spooler service on all Domain Controllers
- Block NTLM outbound traffic from DCs (RestrictSendingNTLMTraffic = 2)
- Enable Extended Protection for Authentication (EPA) on ADCS
- Disable NTLM authentication for ADCS web enrollment
- Apply patches KB5005010 (PrintNightmare), KB5005413 (PetitPotam)

**Verification:**
```powershell
# Verify Print Spooler disabled
Get-Service -Name Spooler -ComputerName DC01,DC02 | 
    Select-Object Name, Status, StartType

# Expected: Status=Stopped, StartType=Disabled

# Verify NTLM outbound blocked on DCs
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic"

# Expected: RestrictSendingNTLMTraffic = 2
```

---

### Technique T1201: Password Policy Discovery

**Description:** Adversaries may attempt to access detailed information about the password policy used within an enterprise network or cloud environment.

**Finding:** H-01 - Weak Password Policy (7 characters)

**Attack Scenario:**
```
1. Attacker gains initial foothold (compromised user account)
2. Runs: net accounts /domain (discovers 7-character minimum)
3. Identifies weak password policy as vulnerability
4. Performs password spraying attack:
   - Tests common 7-character passwords (Winter2023!, Summer2023!, etc.)
   - Avoids account lockout by staying under threshold
5. Compromises multiple user accounts with weak passwords
6. Uses compromised accounts for lateral movement
```

**Mitigation:**
- Increase minimum password length to 12 characters
- Enable password complexity requirements
- Set password history to 24 passwords
- Configure account lockout policy (5 attempts, 30-minute lockout)
- Implement password blacklist (common weak passwords)
- Deploy fine-grained password policies for privileged accounts (14+ characters)

**Verification:**
```powershell
Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength, ComplexityEnabled, PasswordHistoryCount

# Expected:
# MinPasswordLength: 12
# ComplexityEnabled: True
# PasswordHistoryCount: 24
```

---

### Technique T1557: Adversary-in-the-Middle (AitM)

**Description:** Adversaries may attempt to position themselves between two or more networked devices to intercept or modify traffic.

**Findings:**
- M-02 - LDAPS Channel Binding Not Enforced
- M-03 - LDAP Signing Not Required
- M-04 - ADCS Web Enrollment Uses HTTP

**Attack Scenario:**
```
1. Attacker performs ARP spoofing or DNS poisoning
2. Positions themselves between client and domain controller
3. Intercepts LDAP simple binds (no signing required)
4. Captures LDAP credentials in cleartext or downgrades to weak auth
5. Replays or relays credentials to compromise additional systems

OR (ADCS HTTP scenario):
1. Attacker performs MITM attack on certificate enrollment traffic
2. Intercepts HTTP request to http://ca01.contoso.com/certsrv
3. Captures domain credentials in cleartext
4. Uses credentials to request certificates or authenticate to other systems
```

**Mitigation:**
- Require LDAP signing (LDAPServerIntegrity = 2)
- Enable LDAPS channel binding (LdapEnforceChannelBinding = 1)
- Remove HTTP binding from ADCS web enrollment (HTTPS only)
- Deploy SMB signing requirements
- Configure UNC hardened paths

**Verification:**
```powershell
# LDAP Signing
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity"
# Expected: 2

# LDAPS Channel Binding
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding"
# Expected: 1

# ADCS HTTPS Only
Get-WebBinding -Protocol "http" | Where-Object {$_.bindingInformation -like "*certsrv*"}
# Expected: No results (no HTTP binding)
```

---

### Technique T1557.001: LLMNR/NBT-NS Poisoning and SMB Relay

**Description:** Adversaries can spoof an authoritative source for name resolution to force communication with an adversary-controlled system.

**Findings:**
- H-02 - NTLMv1/LM Authentication Enabled
- M-08 - UNC Hardened Paths Not Configured

**Attack Scenario:**
```
1. User attempts to access file share with typo: \\filles01\share (should be \\files01\share)
2. DNS resolution fails
3. System falls back to LLMNR/NetBIOS broadcast
4. Attacker running Responder answers broadcast, impersonating "filles01"
5. User's system attempts NTLM authentication to attacker
6. Attacker captures NTLMv1 hash (weak, can be cracked offline)
7. OR: Attacker relays NTLM authentication to another system (SMB relay attack)
8. Gains unauthorized access using victim's credentials
```

**Mitigation:**
- Ban NTLMv1/LM authentication (LmCompatibilityLevel = 5)
- Disable LLMNR via GPO (EnableMulticast = 0)
- Disable NetBIOS over TCP/IP
- Configure UNC hardened paths (require mutual authentication and integrity)
- Enable SMB signing requirements

**Verification:**
```powershell
# NTLMv1 Ban
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel"
# Expected: 5

# LLMNR Disabled
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast"
# Expected: 0

# UNC Hardened Paths
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
# Expected: \\*\SYSVOL and \\*\NETLOGON configured
```

---

## Cross-Framework Alignment

### ISO 27001 ↔ MITRE ATT&CK Mapping

| ISO 27001:2022 Control | MITRE ATT&CK Techniques Mitigated |
|------------------------|-----------------------------------|
| **5.17 - Authentication Information** | T1078.003 (Local Accounts), T1201 (Password Policy Discovery) |
| **5.18 - Access Rights** | T1078 (Valid Accounts), T1098 (Account Manipulation) |
| **8.2 - Privileged Access Rights** | T1078.002 (Domain Accounts), T1068 (Exploitation for Privilege Escalation) |
| **8.5 - Secure Authentication** | T1557 (AitM), T1557.001 (LLMNR/NBT-NS Poisoning), T1550 (Use Alternate Authentication Material) |
| **8.8 - Technical Vulnerabilities** | T1187 (Forced Authentication), T1210 (Exploitation of Remote Services) |
| **8.15 - Logging** | T1562.002 (Disable Windows Event Logging), T1070 (Indicator Removal) |
| **8.24 - Use of Cryptography** | T1040 (Network Sniffing), T1557 (AitM) |

---

### Additional Framework Alignment

#### NIST Cybersecurity Framework (CSF)

| CSF Function | CSF Category | Related ISO 27001 Controls | Findings Addressed |
|--------------|--------------|---------------------------|-------------------|
| **Identify (ID)** | ID.AM-5: Resources prioritized based on classification | 5.9, 5.12 | All findings (prioritized as HIGH/MEDIUM/LOW) |
| **Protect (PR)** | PR.AC-1: Identities and credentials managed | 5.17, 5.18 | H-01, H-03, M-06, M-07 |
| **Protect (PR)** | PR.AC-7: Users authenticated | 8.5 | H-02, M-02, M-03, M-08 |
| **Protect (PR)** | PR.DS-2: Data-in-transit protected | 8.24 | M-02, M-04 |
| **Protect (PR)** | PR.IP-12: Vulnerability management plan | 8.8 | H-04, H-05 |
| **Detect (DE)** | DE.CM-1: Network monitored | 8.15, 8.16 | M-01 |
| **Detect (DE)** | DE.CM-3: Personnel activity monitored | 8.15 | M-01 |

---

#### CIS Critical Security Controls v8

| CIS Control | Control Title | Related Findings |
|-------------|---------------|------------------|
| **CIS 4** | Secure Configuration of Enterprise Assets and Software | All findings |
| **CIS 5** | Account Management | H-01, H-03, M-06, M-07 |
| **CIS 6** | Access Control Management | H-02, M-06, M-07 |
| **CIS 8** | Audit Log Management | M-01 |
| **CIS 16** | Application Software Security | H-04, H-05 (service hardening) |

---

## Compliance Gap Analysis

### Before Remediation: Gap Summary

| Framework | Compliance % | Critical Gaps |
|-----------|-------------|---------------|
| **ISO 27001:2022** | 42% | 8 controls with major non-conformities |
| **MITRE ATT&CK** | 35% | 5 adversary techniques not mitigated |
| **NIST CSF** | 48% | Protect (PR) and Detect (DE) functions weakest |
| **CIS Controls v8** | 51% | CIS 4, 5, 6 significantly deficient |

---

### After Remediation: Compliance Achievement

| Framework | Compliance % | Residual Gaps |
|-----------|-------------|---------------|
| **ISO 27001:2022** | 92% | Minor improvements needed (L-01 only) |
| **MITRE ATT&CK** | 88% | Advanced persistent threat scenarios remain |
| **NIST CSF** | 87% | Continuous monitoring enhancements recommended |
| **CIS Controls v8** | 85% | Advanced controls (Tier 2/3) for future implementation |

---

[← Back to Main](../README.md)
