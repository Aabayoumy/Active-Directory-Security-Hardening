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

| # | Security Domain | Key Checks |
|---|----------------|------------|
| 1 | Authentication Protocols & Passwords | LM/NTLMv1 support, password policy strength, account lockout, Kerberos encryption |
| 2 | Group Policy Objects (GPOs) | Password policy GPO, security options, audit policy, service configuration |
| 3 | Active Directory Certificate Services (ADCS/PKI) | CA configuration, template permissions, web enrollment (HTTP vs HTTPS), approval requirements |
| 4 | DNS Security | DNSSEC implementation, zone transfer restrictions, dynamic update security |
| 5 | Privileged Group Memberships & Delegations | Schema/Enterprise/Domain Admins membership, custom ACLs, sensitive delegation flag |
| 6 | Domain Controller Security | Service configuration (Print Spooler), LDAP signing, LDAPS channel binding, SMB signing, NTLM restrictions |

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

---

## 4.4 Findings Summary

### HIGH Risk Findings

Detailed remediation for each HIGH risk finding is provided in Chapter 5 (protocol-related) and Chapter 6 (configuration-related).

| ID | Finding | Risk | Remediation Chapter |
|----|---------|------|-------------------|
| **H-01** | Weak Password Policy (Minimum 7 characters) | HIGH | [Chapter 6, Section 6.2.2](06-configuration-hardening.md#622-strengthen-password-policy) |
| **H-02** | NTLMv1/LM Authentication Enabled | HIGH | [Chapter 5, Section 5.2.1](05-protocol-remediation.md#521-ban-ntlmv1lm-authentication) |
| **H-03** | LAPS Not Deployed | HIGH | [Chapter 6, Section 6.2.3](06-configuration-hardening.md#623-deploy-windows-laps) |
| **H-04** | Print Spooler Service Active on Domain Controllers | HIGH | [Chapter 6, Section 6.2.1](06-configuration-hardening.md#621-disable-print-spooler-on-domain-controllers) |
| **H-05** | RPC Coercion Vulnerability (Coercible Interfaces Exposed) | HIGH | [Chapter 5, Section 5.2.2](05-protocol-remediation.md#522-mitigate-rpc-coercion-attacks-restrict-ntlm-outbound) |

### MEDIUM Risk Findings

| ID | Finding | Risk | Remediation Chapter |
|----|---------|------|-------------------|
| **M-01** | DC Audit Baseline Missing | MEDIUM | [Chapter 6, Section 6.3.1](06-configuration-hardening.md#631-apply-domain-controller-audit-baseline) |
| **M-02** | LDAPS Channel Binding Not Enforced | MEDIUM | [Chapter 5, Section 5.3.2](05-protocol-remediation.md#532-ldaps-channel-binding) |
| **M-03** | LDAP Signing Not Required | MEDIUM | [Chapter 5, Section 5.3.1](05-protocol-remediation.md#531-ldap-signing-requirement) |
| **M-04** | ADCS Web Enrollment Uses HTTP | MEDIUM | [Chapter 5, Section 5.3.3](05-protocol-remediation.md#533-secure-adcs-web-enrollment-http-to-https) |
| **M-05** | Missing AD Sites & Subnets | MEDIUM | [Chapter 6, Section 6.5.3](06-configuration-hardening.md#653-configure-ad-sites-and-subnets) |
| **M-06** | Admin Accounts Not Protected from Delegation | MEDIUM | [Chapter 6, Section 6.4.1](06-configuration-hardening.md#641-protect-admin-accounts-from-delegation) |
| **M-07** | Schema Admins Group Not Empty | MEDIUM | [Chapter 6, Section 6.4.2](06-configuration-hardening.md#642-empty-schema-admins-group) |
| **M-08** | UNC Hardened Paths Not Configured | MEDIUM | [Chapter 6, Section 6.5.2](06-configuration-hardening.md#652-configure-unc-hardened-paths) |

### LOW Risk Findings

| ID | Finding | Risk | Remediation Chapter |
|----|---------|------|-------------------|
| **L-01** | AD Recycle Bin Not Enabled | LOW | [Chapter 6, Section 6.5.1](06-configuration-hardening.md#651-enable-ad-recycle-bin) |

---

## 4.5 MITRE ATT&CK Mapping

The following table maps each finding to the MITRE ATT&CK techniques it helps mitigate:

| Technique ID | Technique Name | Related Findings | Risk |
|--------------|----------------|-----------------|------|
| T1078.003 | Valid Accounts: Local Accounts | H-03 (LAPS Not Deployed) | HIGH |
| T1110 | Brute Force | H-01 (Weak Password Policy) | HIGH |
| T1187 | Forced Authentication | H-04 (Print Spooler), H-05 (RPC Coercion) | HIGH |
| T1201 | Password Policy Discovery | H-01 (Weak Password Policy) | HIGH |
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | H-02 (NTLMv1/LM Enabled) | HIGH |
| T1557 | Adversary-in-the-Middle | M-02 (LDAP Channel Binding), M-03 (LDAP Signing), M-08 (UNC Paths) | MEDIUM |
| T1557.001 | LLMNR/NBT-NS Poisoning and SMB Relay | Additional hardening (LLMNR/NetBIOS disable) | MEDIUM |
| T1558 | Steal or Forge Kerberos Tickets | M-01 (Audit Baseline Missing) | MEDIUM |
| T1484 | Domain Policy Modification | M-07 (Schema Admins Not Empty) | MEDIUM |

---

## 4.6 ISO/IEC 27001:2022 Control Mapping

The findings map to the following ISO 27001:2022 controls:

| Control | Title | Related Findings |
|---------|-------|-----------------|
| 5.17 | Authentication Information | H-01 (Password Policy), H-03 (LAPS) |
| 5.18 | Access Rights | H-03 (LAPS), M-06 (Delegation), M-07 (Schema Admins) |
| 5.34 | Privacy and Protection of PII | M-01 (Audit policies) |
| 8.2 | Privileged Access Rights | M-06 (Admin delegation), M-07 (Schema Admins) |
| 8.5 | Secure Authentication | H-02 (NTLM), M-03 (LDAP signing) |
| 8.8 | Management of Technical Vulnerabilities | H-04 (Print Spooler), H-05 (RPC Coercion) |
| 8.13 | Information Backup | L-01 (AD Recycle Bin) |
| 8.15 | Logging | M-01 (Audit baseline) |
| 8.24 | Use of Cryptography | M-02 (LDAPS channel binding), M-04 (ADCS HTTPS) |

---

## 4.7 Compliance Impact

Implementation of the hardening plan supports compliance with:

| Framework | Relevant Requirements |
|-----------|----------------------|
| **NIST Cybersecurity Framework** | All five functions: Identify, Protect, Detect, Respond, Recover |
| **CIS Critical Security Controls** | Controls 4 (Secure Configuration), 5 (Account Management), 6 (Access Control) |
| **PCI DSS** | Requirements 2 (Default passwords), 7 (Access control), 8 (Authentication), 10 (Logging) |
| **GDPR** | Technical measures for data protection (Article 32) |

---

## 4.8 Additional Security Hardening Opportunities

Beyond PingCastle findings, the following security enhancements were identified for implementation:

| Enhancement | Description | Remediation Chapter |
|-------------|-------------|-------------------|
| Secure RDP | NLA, TLS encryption, certificate-based authentication, firewall restrictions | [Chapter 5, Section 5.5.1](05-protocol-remediation.md#551-remote-desktop-protocol-rdp-hardening) |
| Secure WinRM | HTTPS-only listeners, certificate authentication, TrustedHosts restrictions | [Chapter 5, Section 5.5.2](05-protocol-remediation.md#552-windows-remote-management-winrm-hardening) |
| Disable LLMNR | Prevent Link-Local Multicast Name Resolution poisoning | [Chapter 5, Section 5.4.1](05-protocol-remediation.md#541-disable-llmnr-link-local-multicast-name-resolution) |
| Disable NetBIOS | Prevent NetBIOS over TCP/IP poisoning | [Chapter 5, Section 5.4.2](05-protocol-remediation.md#542-disable-netbios-over-tcpip) |
| gMSA Deployment | Automatic password management for service accounts | [Chapter 6, Section 6.6.2](06-configuration-hardening.md#662-implement-group-managed-service-accounts-gmsa) |
| PowerShell Logging | Script block and module logging for security monitoring | [Chapter 6, Section 6.6.1](06-configuration-hardening.md#661-enable-powershell-script-block-logging) |
| Protected Users Group | Enhanced Kerberos-only protection for privileged accounts | [Chapter 6, Section 6.4.1](06-configuration-hardening.md#641-protect-admin-accounts-from-delegation) |

---

## Summary

This chapter presented the security configuration assessment findings from PingCastle analysis of the contoso.com domain:

- **Overall Risk:** HIGH (Health Score: 77/100)
- **Total Findings:** 14 (5 HIGH, 8 MEDIUM, 1 LOW)
- **Critical Issues:** Weak passwords, NTLM vulnerabilities, missing LAPS, Print Spooler, RPC coercion
- **Framework Alignment:** ISO 27001:2022, MITRE ATT&CK, NIST, CIS

Detailed remediation procedures for all findings are provided in:
- **[Chapter 5](05-protocol-remediation.md):** Protocol and authentication remediation (NTLM, RPC, LDAP, ADCS, LLMNR, NetBIOS, RDP, WinRM)
- **[Chapter 6](06-configuration-hardening.md):** Configuration hardening (passwords, LAPS, Print Spooler, audit policies, privileged access, directory features)

---

[← Previous: Laboratory Environment](03-lab-environment.md) | [Next: Mitigating Insecure Protocols and Authentication →](05-protocol-remediation.md)

---

## Resources

- Microsoft security baseline guidance: https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines
- Guidance for securing Active Directory: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices
- PingCastle Active Directory security assessment: https://www.pingcastle.com/documentation/
- MITRE ATT&CK Enterprise techniques: https://attack.mitre.org/techniques/enterprise/
- ISO/IEC 27001:2022 Information security controls: https://www.iso.org/standard/27001
