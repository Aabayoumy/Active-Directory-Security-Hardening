# Chapter 1: Introduction

[← Back to Main](../README.md) | [Next: Background and Related Work →](02-background.md)

---

## 1.1 Overview

Active Directory (AD) is the cornerstone identity and access management system for modern enterprise IT environments. As organizations increasingly rely on AD for authentication, authorization, and resource management, ensuring its security becomes paramount. Windows Server 2022 (November 2025 build) represents Microsoft's latest server platform, yet even with modern security features, default Active Directory installations contain numerous security risks that require systematic assessment and remediation.

This project focuses on **configuration assessment and hardening** of a freshly installed Active Directory forest, identifying security vulnerabilities inherent in default configurations and legacy protocol support. The work emphasizes practical, business-aware remediation strategies rather than theoretical exploitation scenarios.

### Project Context

- **Platform:** Windows Server 2022 (November 2025 build)
- **Scope:** Default Active Directory forest installation
- **Approach:** Automated security configuration assessment using PingCastle
- **Objective:** Identify and mitigate risks from permissive default settings and insecure protocols

### Key Focus Areas

1. **Configuration Assessment:** Analyzing default AD settings using automated tools (PingCastle)
2. **Protocol Security:** Identifying risks from legacy protocols (NTLMv1, unsigned LDAP, LLMNR, NetBIOS)
3. **Security Enhancements:** Implementing additional hardening measures (LAPS, secure RDP/WinRM, audit policies)
4. **Business Continuity:** Ensuring all changes follow detection-first and audit-first methodology

---

## 1.2 Problem Statement

Active Directory installations, even on the latest Windows Server 2022 platform, ship with default configurations that prioritize backward compatibility over security. These defaults create a significant attack surface:

### Default Configuration Risks

- **Weak password policies:** Minimum 7-character passwords by default
- **Legacy protocol support:** NTLMv1 and LM authentication enabled for compatibility
- **Unsigned LDAP:** Directory queries can be transmitted without integrity protection
- **Static local administrator passwords:** Same password across multiple workstations enables lateral movement
- **Unnecessary services:** Print Spooler running on Domain Controllers (PrintNightmare vulnerability)
- **Minimal audit logging:** Insufficient visibility into security events
- **Name resolution vulnerabilities:** LLMNR and NetBIOS-NS enabled by default

### Challenge

Organizations face a dilemma: security best practices often conflict with application compatibility and business operations. Simply applying "hardened" settings without proper assessment can break critical business applications. There is a need for a **systematic, detection-first methodology** that:

1. **Identifies** security risks using automated tools
2. **Audits** current usage patterns before making changes
3. **Assesses** business impact during pilot phases
4. **Implements** remediations with proper testing and rollback procedures
5. **Verifies** successful implementation and ongoing compliance

---

## 1.3 Scope and Objectives

### Scope

This project encompasses:

- **Assessment:** Default Active Directory forest on Windows Server 2022 (November 2025 build)
- **Environment:** Lab-based deployment with 2 Domain Controllers, 1 Certificate Authority, 1 Workstation
- **Analysis:** Configuration security assessment using Netwrix PingCastle Basic Edition
- **Remediation:** Implementation of practical hardening measures aligned with ISO 27001:2022 and MITRE ATT&CK

### Out of Scope

- **NO penetration testing:** This is not a red team engagement
- **NO simulated attacks:** No exploitation or attack simulation activities
- **NO production environment testing:** All work conducted in isolated lab environment

### Key Objectives

1. **Assess default AD security posture** using automated configuration analysis tools (PingCastle)
2. **Identify security risks** from default settings and legacy protocol support
3. **Analyze insecure protocols:** NTLM, unsigned LDAP, RPC, LLMNR, NetBIOS
4. **Recommend practical mitigations** with implementation guidance
5. **Provide additional hardening measures:**
   - Windows LAPS deployment (native to Windows Server 2022)
   - Secure Remote Desktop Protocol (RDP) configuration
   - Secure Windows Remote Management (WinRM) configuration
   - Advanced audit policy implementation
   - AD Recycle Bin and optional features
6. **Develop detection-first framework** with PowerShell automation for:
   - Detection (identify vulnerabilities)
   - Audit mode (monitor business impact)
   - Mitigation (implement fixes)
   - Verification (confirm success)
   - Rollback (restore if needed)

---

## 1.4 Report Organization (Structure)

This report is organized as follows:

### Main Chapters

- **Chapter 1: Introduction** (this chapter) - Project overview, problem statement, scope, and methodology
- **Chapter 2: Background and Related Work** - Literature review of AD security, authentication protocols, and hardening practices
- **Chapter 3: Laboratory Environment** - Lab infrastructure, solution methodology, requirements, and system design
- **Chapter 4: Security Configuration Assessment and Risk Analysis** - PingCastle findings, risk summary, and framework alignment
- **Chapter 5: Mitigating Insecure Protocols and Authentication** - Remediation of NTLM, LDAP, RPC, LLMNR, NetBIOS, RDP, WinRM
- **Chapter 6: Configuration Hardening and Security Enhancements** - Print Spooler, passwords, LAPS, auditing, AD features
- **Chapter 7: Results and Analysis** - Implementation outcomes and security improvements
- **Chapter 8: Conclusion and Future Work** - Summary and recommendations
- **Chapter 9: References** - Bibliography and standards

### Appendices

- **Appendix A:** Project Gantt Chart and Timeline
- **Appendix B:** Secure RDP and WinRM Implementation Guide
- **Appendix C:** Group Managed Service Accounts (gMSA) Guide
- **Appendix D:** PowerShell Script Collection (Detection/Audit/Mitigation)
- **Appendix E:** GPO Baseline Configuration Templates
- **Appendix F:** Lab Topology Diagrams
- **Appendix G:** Compliance Framework Mapping (ISO 27001:2022, MITRE ATT&CK)
- **Appendix H:** Complete VAPT Assessment Report

---

## 1.5 Work Methodology

This project follows a **detection-first, audit-centric approach** to security hardening, ensuring business continuity while improving security posture.

### Core Methodology Principles

1. **No Breaking Changes Without Assessment:** Never implement security controls without first understanding current usage
2. **Audit Mode First:** Enable logging and monitoring before enforcement
3. **Pilot Testing:** Test changes in controlled OUs before domain-wide deployment
4. **Rollback Readiness:** Every change includes documented rollback procedures
5. **Verification Required:** All implementations must be verified with PowerShell commands

### Five-Stage Workflow

```
Detection → Audit → Impact Assessment → Mitigation → Verification
     ↓                                                      ↓
  Identify                                           Confirm Success
  Vulnerability                                      + Rollback Plan
```

### Implementation Process

**Stage 1: Detection**
- Use PingCastle to discover security configuration issues
- Execute PowerShell detection scripts to verify vulnerabilities exist
- Document current insecure state with evidence

**Stage 2: Audit Mode**
- Enable logging and monitoring for the vulnerable component
- Run in audit-only mode for 48-72 hours (or 7 days for major changes)
- Collect data on current usage patterns

**Stage 3: Impact Assessment**
- Analyze audit logs to identify dependencies
- Contact application owners and stakeholders
- Document potential business impact
- Plan communication and change management

**Stage 4: Mitigation**
- Implement security fix in pilot OU first
- Monitor pilot for 7 days
- If successful, roll out domain-wide
- Apply changes during maintenance window

**Stage 5: Verification**
- Execute PowerShell verification scripts
- Confirm security control is functioning
- Document rollback procedure
- Update change management records

### Tools and Techniques

- **Assessment Tool:** Netwrix PingCastle Basic Edition 3.4.1.38
- **Automation:** PowerShell 5.1 / 7+ for all detection, audit, mitigation, and verification tasks
- **Configuration Management:** Group Policy Objects (GPOs) for domain-wide settings
- **Lab Environment:** Isolated AD forest with 2 DCs, 1 CA, 1 workstation

### No Penetration Testing

This project does NOT include:
- Simulated attack campaigns
- Exploitation of vulnerabilities
- Password cracking or hash dumping
- Network traffic interception
- Active reconnaissance or scanning

The work focuses exclusively on **configuration analysis** and **hardening recommendations** based on industry standards (ISO 27001:2022, MITRE ATT&CK, CIS Benchmarks).

---

## 1.6 Work Plan

The project follows a **5-phase implementation timeline** spanning 90 days:

### Phase 1: Planning and Assessment (Days 0-7)

- Lab environment setup and validation
- PingCastle security assessment execution
- Risk analysis and prioritization
- Stakeholder identification
- Change management planning

### Phase 2: Critical Remediations (Days 7-14)

- Print Spooler service disablement (DCs)
- NTLMv1/LM authentication ban
- Password policy strengthening
- Windows LAPS deployment (pilot)
- RPC coercion mitigation

### Phase 3: Protocol Hardening (Days 14-30)

- LDAP signing enforcement
- LDAPS channel binding
- ADCS web enrollment HTTPS migration
- Advanced audit policy implementation
- UNC hardened paths configuration

### Phase 4: Additional Security Enhancements (Days 30-60)

- LLMNR disablement
- NetBIOS over TCP/IP disablement
- Secure RDP configuration
- Secure WinRM configuration
- gMSA implementation
- AD Recycle Bin enablement

### Phase 5: Validation and Documentation (Days 60-90)

- Final security posture re-assessment (PingCastle)
- Verification of all implemented controls
- Documentation completion
- Runbook creation
- Knowledge transfer

### Gantt Chart

Detailed project timeline available in [Appendix A: Gantt Chart](../appendices/appendix-a-gantt-chart.md).

### Risk-Based Prioritization

Remediation priorities align with risk severity:

| Priority | Risk Level | Timeline | Examples |
|----------|-----------|----------|----------|
| Critical | HIGH | 0-14 days | Print Spooler, NTLMv1, LAPS, RPC coercion |
| High | MEDIUM | 14-30 days | LDAP signing, audit policies, channel binding |
| Medium | LOW | 30-90 days | LLMNR, NetBIOS, AD Recycle Bin |

---

## Summary

This introduction chapter established the context, objectives, and methodology for this Active Directory security hardening project. The focus remains on **practical, audit-first configuration assessment** rather than theoretical attacks or penetration testing. The next chapter explores the background and related work in Active Directory security research.

---

[← Back to Main](../README.md) | [Next: Background and Related Work →](02-background.md)
