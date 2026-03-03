# Chapter 2: Background and Related Work (Literature Review)

[← Previous: Introduction](01-introduction.md) | [Next: Laboratory Environment →](03-lab-environment.md)

---

## 2.1 Background

Active Directory (AD) serves as the foundational identity and access management system in modern enterprise environments. First introduced with Windows 2000 Server, Active Directory has evolved to become the de facto standard for centralized authentication, authorization, and resource management in corporate networks.

### Active Directory as Identity Management Foundation

Active Directory provides a hierarchical directory structure based on LDAP (Lightweight Directory Access Protocol), enabling organizations to:

- **Centralized Authentication:** Single sign-on (SSO) for users across network resources
- **Authorization Management:** Role-based access control (RBAC) through group memberships
- **Resource Organization:** Logical grouping of computers, users, and services
- **Policy Enforcement:** Group Policy Objects (GPOs) for configuration management
- **Certificate Services:** Public Key Infrastructure (PKI) through Active Directory Certificate Services (ADCS)

### Default Installation Challenges

Despite its maturity, Active Directory installations face persistent security challenges rooted in default configurations:

**1. Backward Compatibility Requirements**

Microsoft maintains backward compatibility with legacy systems and applications, resulting in:
- Support for deprecated authentication protocols (LM, NTLMv1)
- Weak default password policies (7-character minimum)
- Unsigned LDAP binds accepted by default
- Legacy name resolution protocols (LLMNR, NetBIOS-NS) enabled

**2. Permissive Default Settings**

Default AD installations prioritize ease of deployment over security:
- Minimal audit logging to reduce storage requirements
- Unnecessary services running on Domain Controllers (Print Spooler)
- Static local administrator passwords across workstations
- No protection against credential delegation for privileged accounts

**3. Complexity of Secure Configuration**

Hardening Active Directory requires deep technical knowledge:
- Understanding authentication protocol internals (Kerberos vs. NTLM)
- PKI certificate template security
- Advanced audit policy configuration
- RPC (Remote Procedure Call) filtering and restrictions
- LDAP signing and channel binding requirements

### Attack Surface Analysis

Security researchers have documented numerous attack vectors against default AD configurations:

**Authentication Protocol Attacks:**
- **Pass-the-Hash (PtH):** NTLM hash reuse without knowing plaintext password
- **NTLM Relay:** Relaying NTLM authentication to gain unauthorized access
- **Kerberoasting:** Extracting service account credentials via TGS requests
- **AS-REP Roasting:** Attacking accounts with Kerberos pre-authentication disabled

**Name Resolution Poisoning:**
- **LLMNR/NBT-NS Poisoning:** Intercepting name resolution requests to capture credentials
- **WPAD Attacks:** Web Proxy Auto-Discovery exploitation

**Coercion Attacks:**
- **PrintNightmare (CVE-2021-34527):** Print Spooler remote code execution
- **PetitPotam (CVE-2021-36942):** Forcing DC authentication via RPC
- **DFSCoerce:** Distributed File System RPC coercion

**Certificate Services (ADCS) Attacks:**
- **ESC1-ESC8:** Certificate template misconfigurations enabling privilege escalation

While this project does NOT perform these attacks, understanding the threat landscape informs the hardening strategy.

---

## 2.2 Literature Survey

The literature on Active Directory security spans Microsoft official guidance, industry standards, security frameworks, and academic research.

### 2.2.1 Authentication Protocols

**NTLM (NT LAN Manager) vs. Kerberos**

NTLM represents legacy Microsoft authentication, operating as a challenge-response protocol:

- **NTLM Versions:**
  - **LM (LAN Manager):** Extremely weak, uses DES encryption (deprecated since Windows Vista)
  - **NTLMv1:** Vulnerable to pass-the-hash and relay attacks
  - **NTLMv2:** Improved but still susceptible to relay attacks

- **Security Concerns:**
  - No mutual authentication (only client authenticates to server)
  - Vulnerable to relay attacks even with NTLMv2
  - Hash can be reused without plaintext password (pass-the-hash)
  - No support for modern cryptographic standards

**Kerberos** is the preferred authentication protocol for AD:

- **Advantages:**
  - Mutual authentication (both client and server verify identity)
  - Ticket-based authentication (no password transmission)
  - Time-limited tickets reduce credential reuse risk
  - Support for modern encryption algorithms (AES-128, AES-256)

- **Microsoft Recommendations (2023-2024):**
  - Disable NTLMv1 and LM authentication
  - Audit NTLM usage before enforcement
  - Gradually transition to Kerberos-only authentication
  - Block NTLM for Domain Controllers and privileged accounts

**Industry Guidance:**
- NIST SP 800-63B: Recommends phasing out NTLM
- Canadian Centre for Cyber Security: Advocates Kerberos-only environments
- CIS Microsoft Windows Server 2022 Benchmark: Requires NTLMv2 minimum (Level 1), recommends Kerberos-only (Level 2)

### 2.2.2 Password Policies

**Default Windows Server Password Policy:**

Windows Server 2022 ships with minimal password requirements:
- Minimum password length: 7 characters
- Password complexity: Enabled (3 of 4 character types)
- Maximum password age: 42 days
- Password history: 24 passwords

**Current Best Practices (2024-2025):**

**NIST SP 800-63B (Digital Identity Guidelines):**
- Minimum 8 characters for user-chosen passwords
- Minimum 12-15 characters recommended for administrative accounts
- Screen against common password lists
- No mandatory periodic password changes unless compromise suspected
- No composition rules (complexity can reduce entropy)

**Microsoft Security Baseline (Windows Server 2022):**
- Minimum password length: 14 characters
- Account lockout threshold: 10 invalid attempts
- Account lockout duration: 15 minutes
- Password history: 24 passwords remembered

**ISO/IEC 27001:2022 Controls:**
- Control 5.17: Authentication information management
- Control 5.18: Access rights management
- Emphasis on strong, unique passwords for privileged accounts

**Fine-Grained Password Policies (FGPP):**

Windows Server 2008+ supports multiple password policies per domain:
- Different policies for user groups (e.g., administrators vs. standard users)
- Higher security requirements for privileged accounts
- Configured via The Active Directory Administrative Center (ADAC) or PowerShell

### 2.2.3 Secure Directory Access (LDAP/LDAPS)

**LDAP Security Mechanisms:**

Active Directory supports multiple LDAP security features:

**1. LDAP Signing:**
- Ensures integrity of LDAP traffic (prevents tampering)
- Can be optional (value 1) or required (value 2)
- Registry key: `LDAPServerIntegrity`

**2. LDAP Channel Binding:**
- Binds LDAP authentication to TLS channel
- Prevents LDAP relay attacks over LDAPS
- Registry key: `LdapEnforceChannelBinding`

**3. LDAPS (LDAP over SSL/TLS):**
- Encrypts LDAP traffic using SSL/TLS (port 636)
- Requires domain controller certificates
- Protects confidentiality of directory queries

**Microsoft Advisories:**

- **March 2020 LDAP Signing and Channel Binding Advisory:**
  - CVE-2017-8563: LDAP relay vulnerabilities
  - Phased enforcement timeline (audit mode → enforcement)
  - Recommendations for identifying affected clients

**Security Benefits:**
- Prevents man-in-the-middle (MitM) attacks on LDAP
- Protects against LDAP relay to ADCS (ESC8 attack)
- Ensures integrity of Group Policy downloads
- Secures sensitive attribute queries (passwords, group memberships)

### 2.2.4 Privilege Management (LAPS)

**Local Administrator Password Solution (LAPS):**

Static local administrator passwords represent a critical security gap:
- Same password across multiple workstations enables lateral movement
- Compromised single workstation exposes entire fleet
- Difficulty in tracking password changes

**Traditional LAPS (Microsoft LAPS - Legacy):**
- Separate download and AD schema extension required
- Stores passwords in `ms-Mcs-AdmPwd` attribute (clear text in AD)
- Requires explicit permission delegation for password retrieval
- Passwords automatically rotate on schedule

**Windows LAPS (Native to Windows 11 / Server 2022):**

Microsoft integrated LAPS natively starting with Windows 11 and Windows Server 2022:

- **No Schema Extension Required:** Uses existing AD infrastructure
- **Built-In Functionality:** No separate MSI installation
- **Enhanced Features:**
  - Support for both Azure AD and on-premises AD
  - Password encryption in transit
  - Configurable password complexity and rotation
  - Backup to Active Directory and/or Azure AD

**Windows LAPS Configuration:**
- Configured via Group Policy: `Computer Configuration → Administrative Templates → System → LAPS`
- PowerShell management via built-in cmdlets
- Supports different administrator account names
- Password age configurable (default: 30 days)

**Security Benefits:**
- Eliminates shared local administrator passwords
- Prevents lateral movement via local admin accounts
- Automatic password rotation
- Auditable password retrievals
- Reduces risk of credential dumping attacks

**Compliance Alignment:**
- ISO 27001:2022 Control 5.18: Access rights management
- MITRE ATT&CK T1078.003: Valid Accounts - Local Accounts mitigation
- CIS Control 5: Account Management

### 2.2.5 Domain Controller Hardening

**Print Spooler Service:**

The Windows Print Spooler service has been the source of critical vulnerabilities:

- **PrintNightmare (CVE-2021-34527):**
  - Remote code execution on servers with Print Spooler running
  - Allows privilege escalation to SYSTEM
  - Affects Domain Controllers if Print Spooler enabled

**Microsoft Guidance:**
- Disable Print Spooler on Domain Controllers (DCs rarely need printing)
- Apply KB5004945 and subsequent patches
- Monitor Event ID 808 for Print Spooler activity

**RPC (Remote Procedure Call) Coercion:**

RPC interfaces on Domain Controllers can be abused to force authentication:

- **PetitPotam (CVE-2021-36942):**
  - Forces DC to authenticate to attacker-controlled system
  - Enables NTLM relay to ADCS for certificate request
  - Mitigated by restricting NTLM outbound traffic from DCs

**Mitigation Strategies:**
- Block NTLM outbound from Domain Controllers
- Enable Extended Protection for Authentication (EPA)
- Apply RPC filters to limit exposure

### 2.2.6 Certificate Services (ADCS/PKI) Security

**Active Directory Certificate Services** provides PKI infrastructure but introduces attack surface if misconfigured:

**Certificate Template Vulnerabilities (ESC1-ESC8):**

Security researchers (Will Schroeder, Lee Christensen) documented ADCS attack primitives:

- **ESC1:** Domain authentication templates with overly permissive enrollment
- **ESC2:** Any purpose certificate templates
- **ESC3:** Enrollment agent templates
- **ESC4:** Vulnerable certificate template ACLs
- **ESC6:** EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled
- **ESC7:** Vulnerable CA ACLs
- **ESC8:** NTLM relay to HTTP enrollment endpoints

**Hardening ADCS:**
- Remove HTTP bindings from Certificate Enrollment web interfaces (use HTTPS only)
- Disable EDITF_ATTRIBUTESUBJECTALTNAME2 flag
- Review certificate template permissions
- Enable manager approval for high-value templates
- Implement certificate request auditing

**PingCastle Assessment:**

PingCastle specifically checks for:
- HTTP vs. HTTPS enrollment endpoints
- Weak certificate template configurations
- CA permissions and delegations

---

## 2.3 Analysis of the Related Work

### Security vs. Business Continuity Tension

A common theme across all reviewed literature is the inherent tension between security hardening and business continuity:

**The Challenge:**
- Disabling NTLM may break legacy applications
- Requiring LDAP signing may affect third-party directory-integrated tools
- Password policy changes impact users and helpdesk
- Service disabling can break dependencies

**Traditional Approaches:**

1. **"Rip and Replace" Hardening:**
   - Apply all security baselines immediately
   - High risk of service disruption
   - Often requires extensive rollback

2. **"Penetration Testing First" Approach:**
   - Perform red team engagement to identify vulnerabilities
   - Exploit findings to demonstrate risk
   - Remediate based on successful attacks

3. **"Configuration Baseline" Approach:**
   - Apply vendor security baselines (Microsoft, CIS)
   - Test in isolated environment
   - Deploy to production after validation

### "Detection and Audit" Methodology

This project adopts a distinct approach combining elements of configuration assessment with audit-first implementation:

**Key Differentiators:**

1. **No Exploitation Required:**
   - Risks identified through configuration assessment (PingCastle)
   - No need for simulated attacks to demonstrate vulnerability
   - Automated rule-based analysis

2. **Audit Mode Before Enforcement:**
   - Every change begins with logging/monitoring
   - Business impact assessed during audit period (48-72 hours typical)
   - Data-driven decision making

3. **Phased Rollout with Pilot Testing:**
   - Test in pilot OU before domain-wide deployment
   - Monitor for issues during controlled rollout
   - Rollback procedures documented

4. **PowerShell Automation:**
   - Detection scripts verify vulnerability exists
   - Audit scripts enable monitoring
   - Mitigation scripts implement fixes
   - Verification scripts confirm success
   - Rollback scripts restore previous state

**Comparison Table:**

| Aspect | Traditional Pen Test | Baseline Hardening | Detection & Audit (This Project) |
|--------|---------------------|-------------------|----------------------------------|
| Vulnerability Discovery | Manual exploitation | Checklist/benchmark | Automated assessment (PingCastle) |
| Risk Validation | Successful attack | Configuration review | Rule-based detection |
| Business Impact Assessment | Post-exploitation | Pre-deployment testing | Audit mode monitoring |
| Deployment Method | Reactive fixes | All-at-once | Phased with pilot OUs |
| Rollback Plan | Often missing | Pre-tested | Documented per change |
| Stakeholder Engagement | After demonstration | Before deployment | During audit period |

### Alignment with Industry Frameworks

**ISO/IEC 27001:2022:**

The project aligns with multiple ISO 27001:2022 controls:

- **Control 5.17 (Authentication Information):** Password policies, LAPS deployment
- **Control 5.18 (Access Rights):** Privileged account protection, delegation restrictions
- **Control 8.2 (Privileged Access Rights):** Admin account hardening, tiered access
- **Control 8.5 (Secure Authentication):** NTLM deprecation, Kerberos enforcement
- **Control 8.8 (Management of Technical Vulnerabilities):** Print Spooler, RPC coercion
- **Control 8.15 (Logging):** Advanced audit policy, PowerShell logging
- **Control 8.24 (Use of Cryptography):** LDAPS, RDP/WinRM encryption

**MITRE ATT&CK Framework:**

Hardening measures directly mitigate documented adversary techniques:

- **T1078.003 (Valid Accounts: Local Accounts):** LAPS deployment
- **T1187 (Forced Authentication):** Print Spooler, RPC coercion mitigation
- **T1557.001 (LLMNR/NBT-NS Poisoning):** Name resolution protocol disablement
- **T1201 (Password Policy Discovery):** Strong password policies
- **T1550.002 (Pass the Hash):** NTLM restrictions

**NIST Cybersecurity Framework:**

- **Identify (ID.RA):** PingCastle risk assessment
- **Protect (PR.AC):** Authentication hardening, privilege management
- **Detect (DE.CM):** Advanced audit policies, logging
- **Respond (RS.MI):** Documented rollback procedures
- **Recover (RC.RP):** AD Recycle Bin, change management

### Comparison with Standard Hardening Approaches

**Microsoft Security Baselines:**

Microsoft publishes security baseline GPOs for Windows Server:
- Comprehensive but sometimes overly restrictive
- Limited guidance on audit-first deployment
- Assumes isolated testing environment available

**This Project's Approach:**
- Uses Microsoft baselines as reference
- Adds audit mode step before enforcement
- Provides PowerShell automation for detection and verification
- Includes business impact assessment methodology

**CIS Benchmarks:**

CIS (Center for Internet Security) publishes detailed benchmarks:
- Prescriptive configuration recommendations
- Level 1 (minimal impact) vs. Level 2 (higher security)
- Extensive documentation

**This Project's Approach:**
- Aligns with CIS recommendations
- Adds automated detection via PingCastle
- Emphasizes phased deployment
- Includes rollback procedures not in CIS documentation

### Gap Analysis

**What Existing Approaches Miss:**

1. **Audit-First Workflow:** Most guides recommend immediate enforcement without audit mode
2. **PowerShell Automation:** Limited scripting for detection and verification
3. **Rollback Procedures:** Often missing or incomplete
4. **Business Impact Assessment:** Minimal guidance on assessing organizational impact
5. **Tool-Assisted Assessment:** Heavy reliance on manual checklist reviews

**This Project's Contributions:**

1. Complete PowerShell workflow for each remediation
2. Standardized Detection → Audit → Mitigation → Verification pattern
3. PingCastle automated assessment integration
4. Documented rollback for every change
5. Framework alignment (ISO 27001, MITRE ATT&CK)

---

## Summary

This chapter explored the background and related work in Active Directory security, covering:

- Active Directory's role as identity management foundation
- Default configuration challenges and attack surface
- Literature on authentication protocols, password policies, LDAP security, and privilege management
- Analysis of security vs. business continuity tensions
- Comparison of detection-first methodology with traditional approaches
- Alignment with ISO 27001, MITRE ATT&CK, and NIST frameworks

The next chapter details the laboratory environment and solution methodology used to implement the detection-first hardening approach.

---

[← Previous: Introduction](01-introduction.md) | [Next: Laboratory Environment →](03-lab-environment.md)

---

## Resources

- Windows Server security overview: https://learn.microsoft.com/en-us/windows-server/security/windows-server-security
- Authentication protocols in Windows: https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview
