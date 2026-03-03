# Chapter 3: Laboratory Environment

[← Previous: Background and Related Work](02-background.md) | [Next: Security Configuration Assessment and Risk Analysis →](04-security-assessment.md)

---

## 3.1 Lab Infrastructure

This project utilizes an isolated laboratory environment to assess and harden Active Directory configurations without impacting production systems. The lab infrastructure mirrors a typical small-to-medium enterprise AD deployment.

### Overview

The lab consists of four virtual machines deployed in an isolated network:

- **Domain Controllers (2):** Primary and secondary DCs providing redundancy
- **Certificate Authority (1):** Standalone Enterprise CA for PKI services
- **Client Workstation (1):** Windows 11 domain-joined machine for testing

All systems run the latest available builds as of the project start date.

### Component Details

#### Domain Controllers

**DC01 (Primary Domain Controller):**
- **Operating System:** Windows Server 2022 (November 2025 build)
- **Hostname:** DC01.contoso.com
- **IP Address:** 192.168.51.10
- **Roles:**
  - Active Directory Domain Services (AD DS)
  - DNS Server
  - Global Catalog
  - FSMO Roles: Schema Master, Domain Naming Master, PDC Emulator, RID Master, Infrastructure Master
- **Specifications:**
  - vCPU: 4 cores
  - RAM: 8 GB
  - Disk: 80 GB

**DC02 (Secondary Domain Controller):**
- **Operating System:** Windows Server 2022 (November 2025 build)
- **Hostname:** DC02.contoso.com
- **IP Address:** 192.168.51.11
- **Roles:**
  - Active Directory Domain Services (AD DS)
  - DNS Server
  - Global Catalog
- **Specifications:**
  - vCPU: 4 cores
  - RAM: 8 GB
  - Disk: 80 GB

#### Certificate Authority

**CA01 (Enterprise Certificate Authority):**
- **Operating System:** Windows Server 2022 (November 2025 build)
- **Hostname:** CA01.contoso.com
- **IP Address:** 192.168.51.12
- **Roles:**
  - Active Directory Certificate Services (AD CS)
  - Enterprise Root CA
  - Web Enrollment (HTTP and HTTPS - to be hardened)
- **Specifications:**
  - vCPU: 2 cores
  - RAM: 4 GB
  - Disk: 60 GB

#### Client Workstation

**WS01 (Windows 11 Workstation):**
- **Operating System:** Windows 11 Enterprise (23H2)
- **Hostname:** WS01.contoso.com
- **IP Address:** 192.168.51.20
- **Configuration:**
  - Domain-joined to contoso.com
  - Standard user and administrator accounts for testing
- **Specifications:**
  - vCPU: 2 cores
  - RAM: 8 GB
  - Disk: 80 GB

### Network Architecture

**Network Configuration:**
- **Domain:** contoso.com
- **Forest Functional Level:** Windows Server 2016
- **Domain Functional Level:** Windows Server 2016
- **Network Segment:** 192.168.51.0/24
- **DNS:** DC01 and DC02 (192.168.51.10, 192.168.51.11)
- **Gateway:** 192.168.51.1 (firewall to external networks)

**Isolation:**
- Lab network isolated from production via dedicated VLAN
- No inbound connectivity from corporate network
- Limited outbound access for Windows Update and tool downloads
- No internet access for domain controllers (by design)

**Network Services:**
- DNS: Handled by Domain Controllers
- DHCP: Static IP assignments for all lab systems
- Time Sync: DC01 acts as authoritative time source (syncs to external NTP)

### Active Directory Structure

**Forest Configuration:**
- **Forest Name:** contoso.com
- **Single Domain:** contoso.com
- **Domain Controllers:** 2 (DC01, DC02)
- **Sites:** Default-First-Site-Name (single site)

**Organizational Units (OUs):**

```
contoso.com
├── Domain Controllers (default)
├── Computers (default)
├── Users (default)
├── LAPS-Pilot (created for testing)
├── Servers
│   └── CA01
└── Workstations
    └── WS01
```

**User Accounts:**
- **Administrator:** Built-in domain administrator (protected)
- **ahmed.bayoumy:** Domain administrator account for project work
- **testuser01-05:** Standard domain user accounts for testing
- **svc-test:** Service account for testing LAPS and gMSA

**Group Memberships:**
- ahmed.bayoumy: Domain Admins, Enterprise Admins (temporary for setup)
- Standard security groups: Domain Users, Domain Computers, etc.

### Lab Environment Deployment

The lab was deployed following these steps:

1. **Virtualization Platform:** VMware Workstation Pro 17
2. **Base OS Installation:** Windows Server 2022 and Windows 11 from Microsoft ISO
3. **AD Forest Creation:** Promoted DC01 with `Install-ADDSForest`
4. **Secondary DC Deployment:** Promoted DC02 with `Install-ADDSDomainController`
5. **Certificate Authority Installation:** Configured Enterprise Root CA on CA01
6. **Client Join:** Joined WS01 to contoso.com domain
7. **Baseline Configuration:** Applied minimal configuration for functionality
8. **Snapshot:** Created clean baseline snapshots before assessment

**Lab Readiness Checklist:**
- ✓ AD forest fully functional
- ✓ DNS resolution working
- ✓ Kerberos authentication functional
- ✓ Certificate Authority issuing certificates
- ✓ Group Policy applying successfully
- ✓ No hardening applied (default Microsoft configuration)
- ✓ PingCastle assessment tool installed on DC01

---

## 3.2 Solution Methodology

This project implements a **Detection-First Framework** to identify and remediate Active Directory security vulnerabilities while maintaining business continuity.

### Core Principles

1. **Identify Before Remediate:** Use automated tools to discover vulnerabilities
2. **Audit Before Enforce:** Enable monitoring to understand impact before applying restrictions
3. **Test Before Deploy:** Pilot changes in controlled OUs before domain-wide rollout
4. **Document Everything:** Every change includes detection, mitigation, verification, and rollback procedures

### Three-Stage Process

The solution methodology follows three distinct stages:

#### Stage 1: Detection & Analysis

**Objective:** Identify security configuration issues using automated assessment tools

**Activities:**
1. Execute PingCastle security assessment against contoso.com domain
2. Review PingCastle report and risk scoring (Health Check)
3. Categorize findings by risk level (HIGH, MEDIUM, LOW)
4. Map findings to industry frameworks (ISO 27001, MITRE ATT&CK)
5. Prioritize remediation based on risk and business impact

**Tools:**
- Netwrix PingCastle Basic Edition 3.4.1.38
- PowerShell detection scripts
- Event Viewer for current logging state

**Deliverables:**
- PingCastle HTML and XML reports
- Risk assessment summary
- Prioritized remediation roadmap

#### Stage 2: Impact Validation

**Objective:** Assess business impact of potential hardening changes through audit mode

**Activities:**
1. **Enable Audit Mode:** Configure logging/monitoring without enforcement
2. **Monitor Usage:** Collect data for 48-72 hours (or 7 days for critical changes)
3. **Analyze Logs:** Identify systems, applications, and users affected
4. **Stakeholder Engagement:** Contact application owners and users
5. **Document Dependencies:** Record legitimate use cases requiring consideration

**Audit Mode Implementation:**

For each remediation category:

| Category | Audit Method | Duration | Monitoring |
|----------|-------------|----------|------------|
| NTLM Usage | Enable NTLM auditing (Event 4624) | 48-72 hours | Identify clients using NTLM |
| LDAP Signing | LDAP diagnostics (Event 2889) | 48-72 hours | Find unsigned LDAP binds |
| Print Spooler | Review print jobs and printers | Immediate | Verify no printing on DCs |
| LAPS Pilot | Deploy to test OU only | 7 days | Test password rotation |
| LLMNR/NetBIOS | Deploy to pilot OU | 7 days | Monitor name resolution failures |
| RDP/WinRM | Review access logs | 48 hours | Identify legitimate users |

**Risk Assessment During Audit:**
- Low Impact: Proceed with mitigation
- Medium Impact: Plan communication and extended testing
- High Impact: Escalate to stakeholders, consider exceptions or delayed timeline

#### Stage 3: Phased Mitigation

**Objective:** Implement security hardening in controlled phases with rollback capability

**Phased Rollout Approach:**

**Phase 1: Pilot OU (Week 1)**
- Apply changes to LAPS-Pilot OU (2-3 test computers)
- Monitor for issues daily
- Validate functionality
- Gather user feedback

**Phase 2: Extended Pilot (Week 2)**
- Expand to additional test OUs if Phase 1 successful
- Include diverse system types (servers, workstations)
- Monitor helpdesk tickets
- Confirm no service disruptions

**Phase 3: Production Rollout (Week 3+)**
- Deploy domain-wide via Group Policy or PowerShell
- Staged rollout (e.g., 25% → 50% → 100%)
- Maintain rollback readiness
- Document final configuration

**Change Management Integration:**
- Each change requires change management ticket
- Business justification documented
- Stakeholder approval obtained
- Implementation window scheduled
- Rollback plan tested

**Verification Requirements:**

Every mitigation must include:
1. **Pre-Implementation Check:** PowerShell script confirming vulnerability exists
2. **Post-Implementation Verification:** PowerShell script confirming fix applied
3. **Functionality Test:** Confirm business operations unaffected
4. **Rollback Test:** Verify rollback procedure works in pilot

---

## 3.3 Functional and Non-functional Requirements

### Functional Requirements

The hardening solution must address the following security requirements:

**FR-1: NTLM Detection and Restriction**
- Detect current NTLM usage across domain
- Enable NTLM auditing
- Restrict or disable NTLM where feasible
- Maintain compatibility with applications requiring NTLM (if any)

**FR-2: Password Policy Enhancement**
- Enforce minimum 12-character passwords
- Maintain password history (24 passwords)
- Enable password complexity
- Configure account lockout policies

**FR-3: Service Hardening**
- Disable Print Spooler on Domain Controllers
- Remove unnecessary services
- Apply principle of least functionality

**FR-4: Local Administrator Password Management**
- Deploy Windows LAPS to manage local administrator passwords
- Automate password rotation (30-day cycle)
- Implement secure password retrieval process
- Audit password access

**FR-5: LDAP Security**
- Require LDAP signing for directory queries
- Enable LDAPS channel binding
- Monitor for unsigned LDAP binds during audit period

**FR-6: Certificate Services Security**
- Remove HTTP binding from ADCS web enrollment
- Enforce HTTPS-only certificate enrollment
- Review certificate template permissions

**FR-7: RPC Coercion Mitigation**
- Restrict NTLM outbound traffic from Domain Controllers
- Monitor for legitimate outbound NTLM usage (should be none)

**FR-8: Name Resolution Hardening**
- Disable LLMNR (Link-Local Multicast Name Resolution)
- Disable NetBIOS over TCP/IP
- Ensure DNS as sole name resolution method

**FR-9: Remote Access Security**
- Enable Network Level Authentication (NLA) for RDP
- Configure RDP to use High encryption
- Migrate WinRM from HTTP to HTTPS
- Restrict remote access to authorized administrators

**FR-10: Audit and Logging**
- Implement Advanced Audit Policy for Domain Controllers
- Enable PowerShell script block logging
- Configure event log forwarding to SIEM (if available)
- Monitor critical security events

**FR-11: Privileged Account Protection**
- Set "Account is sensitive and cannot be delegated" flag for admin accounts
- Empty Schema Admins group (just-in-time access model)
- Add eligible accounts to Protected Users group

**FR-12: Directory Recovery**
- Enable AD Recycle Bin
- Configure proper AD Sites and Subnets
- Implement UNC hardened paths

### Non-functional Requirements

**NFR-1: Compatibility**
- All changes must maintain compatibility with Windows 11 and Windows Server 2022
- Existing Group Policy functionality must remain operational
- Certificate-based authentication must continue working
- Kerberos authentication must not be disrupted

**NFR-2: Auditability**
- All configuration changes must be auditable via Event Viewer or PowerShell
- Detection scripts must clearly identify vulnerable configurations
- Verification scripts must confirm successful implementation
- Rollback procedures must be documented and tested

**NFR-3: Performance**
- Hardening changes must not significantly impact system performance
- LDAP signing may add minimal CPU overhead (<5% acceptable)
- Advanced audit policies may increase log volume (plan for storage)
- No impact to user logon times acceptable (target: <500ms increase)

**NFR-4: Scalability**
- Solution must scale to larger AD environments (beyond 4-system lab)
- PowerShell scripts should support remote execution at scale
- Group Policy preferred over per-system configuration
- Consideration for multi-site AD deployments

**NFR-5: Maintainability**
- Configuration documented in version-controlled scripts
- Group Policy settings exported and backed up
- Regular reassessment (quarterly PingCastle scans)
- Runbooks created for common troubleshooting scenarios

**NFR-6: Recoverability**
- Every change includes tested rollback procedure
- Domain Controller snapshots taken before critical changes
- Pilot OUs used to test rollback before production deployment
- AD forest backups scheduled

**NFR-7: Compliance**
- Alignment with ISO/IEC 27001:2022 controls
- Mapping to MITRE ATT&CK techniques
- Consideration for NIST Cybersecurity Framework
- Documentation suitable for compliance audits

---

## 3.4 System Analysis & Design

This section presents the target security architecture after implementing all hardening measures.

### Hardened Baseline Architecture

The target architecture implements defense-in-depth across multiple layers:

**Layer 1: Authentication & Authorization**
- Kerberos as primary authentication protocol
- NTLMv2 minimum (NTLMv1/LM disabled)
- NTLM outbound blocked from Domain Controllers
- Strong password policies (12+ characters)
- Multi-factor authentication ready (infrastructure prepared)

**Layer 2: Privileged Access Management**
- Windows LAPS managing local administrator passwords
- Protected Users group for Tier 0 administrators
- "Sensitive and cannot be delegated" flag for admin accounts
- Just-in-time access for Schema Admins
- Separate administrative accounts (no day-to-day use of admin credentials)

**Layer 3: Encrypted Communication**
- LDAP signing required
- LDAPS channel binding enforced
- HTTPS-only for ADCS web enrollment
- RDP with NLA and High encryption
- WinRM HTTPS-only (no HTTP listeners)

**Layer 4: Service Hardening**
- Print Spooler disabled on Domain Controllers
- Unnecessary services removed
- RPC filters applied to limit attack surface
- UNC hardened paths protecting SYSVOL and NETLOGON

**Layer 5: Audit & Monitoring**
- Advanced audit policy capturing critical events
- PowerShell script block logging
- NTLM usage auditing (even after restrictions)
- Event log forwarding to centralized SIEM
- Regular PingCastle assessments (quarterly)

**Layer 6: Directory Resilience**
- AD Recycle Bin enabled
- Proper AD Sites and Subnets configuration
- Regular AD backups
- FSMO role monitoring

### Secure Authentication Tiering

The design follows Microsoft's tiered administration model concepts:

**Tier 0 (Control Plane):**
- Domain Controllers (DC01, DC02)
- Certificate Authority (CA01)
- Enterprise Admins, Schema Admins, Domain Admins
- Managed by dedicated Tier 0 administrative accounts
- Protected by strictest security controls

**Tier 1 (Application/Server Tier):**
- Member servers (if present beyond lab)
- Server administrators
- Service accounts (gMSA where possible)
- Cannot manage Tier 0, can manage Tier 2

**Tier 2 (Workstation/User Tier):**
- User workstations (WS01)
- Standard users
- Helpdesk administrators
- Cannot manage Tier 0 or Tier 1

**Tier Enforcement:**
- Tier 0 admins do NOT log on to Tier 1 or Tier 2 systems
- Credential Guard and Remote Credential Guard prevent credential theft
- Protected Users group enforces Kerberos-only authentication for Tier 0

### Encrypted Communication Paths

All sensitive communications encrypted:

```
[Client] --LDAPS (636)--> [Domain Controller]
[Client] --Kerberos (88)--> [Domain Controller]
[Admin] --RDP+NLA (3389)--> [Server]
[Script] --WinRM HTTPS (5986)--> [Server]
[User] --HTTPS (443)--> [Certificate Authority Web Enrollment]
```

**Legacy Protocols Restricted:**
- NTLM: Monitored and restricted (outbound blocked on DCs)
- LDAP unsigned: Rejected (signing required)
- LLMNR/NetBIOS-NS: Disabled
- HTTP web enrollment: Removed

### Isolated Administrative Access

**Administrative Workstations (Future Enhancement):**

While not implemented in this lab, the design supports future deployment of Privileged Access Workstations (PAWs):

- Dedicated workstations for Tier 0 administration
- No internet browsing or email from PAWs
- Enhanced security monitoring
- Restricted application execution (AppLocker/WDAC)

**Current Lab Implementation:**
- Administrative access restricted to known IP addresses
- RDP/WinRM firewall rules limit access
- Administrative accounts use separate credentials (not user accounts)

### Security Monitoring & Alerting

**Event Monitoring Strategy:**

Critical events monitored via Event Viewer (future SIEM integration):

| Event Category | Event IDs | Purpose |
|----------------|-----------|---------|
| Account Logon | 4768, 4769, 4771 | Kerberos authentication monitoring |
| Logon/Logoff | 4624, 4625, 4634 | Track successful and failed logons |
| Account Management | 4720, 4722, 4724, 4738 | User/group modifications |
| Privilege Use | 4672, 4673 | Administrative action tracking |
| NTLM Auditing | 8004, 8005, 8006 | NTLM usage monitoring |
| LDAP Diagnostics | 2889, 3039, 3040 | LDAP signing and channel binding |
| PowerShell | 4104 | Script block logging |

**Alerting Criteria:**
- Failed Tier 0 admin logons
- Unexpected NTLM usage from Domain Controllers
- Unsigned LDAP binds after enforcement
- Schema modifications
- Privileged group membership changes

### Configuration Management

**Group Policy Structure:**

Proposed GPO organization for hardened environment:

```
contoso.com
├── Default Domain Policy (modified: password policy)
├── Default Domain Controllers Policy (modified: audit policy)
├── Security Baseline - Domain Controllers
│   ├── NTLM Restrictions
│   ├── LDAP Signing
│   ├── Service Hardening
│   └── RPC Filters
├── Security Baseline - Servers
│   ├── LAPS Configuration
│   ├── RDP Hardening
│   ├── WinRM HTTPS
│   └── Audit Policies
└── Security Baseline - Workstations
    ├── LAPS Configuration
    ├── LLMNR/NetBIOS Disable
    ├── UNC Hardened Paths
    └── PowerShell Logging
```

**PowerShell Desired State Configuration (Future):**

While not implemented in this project, the design supports future DSC integration for:
- Automated compliance monitoring
- Configuration drift detection
- Automated remediation

---

## Summary

This chapter detailed the laboratory environment used for Active Directory security assessment and hardening:

- **Lab Infrastructure:** 4-system isolated environment (2 DCs, 1 CA, 1 workstation)
- **Solution Methodology:** Three-stage Detection-First framework
- **Requirements:** Functional and non-functional requirements for hardening solution
- **Target Architecture:** Hardened baseline with defense-in-depth, secure authentication tiering, encrypted communications, and comprehensive monitoring

The next chapter presents the security configuration assessment findings from the PingCastle automated assessment tool.

---

[← Previous: Background and Related Work](02-background.md) | [Next: Security Configuration Assessment and Risk Analysis →](04-security-assessment.md)

---

## Resources

- AD DS design and planning: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/active-directory-domain-services-design-guide
- Securing privileged access (tier model): https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material
