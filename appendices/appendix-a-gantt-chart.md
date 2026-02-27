[← Back to Main](../README.md)

# Appendix A: Project Gantt Chart and Timeline

## 5-Phase Project Timeline (90-Day Implementation)

This Gantt chart visualizes the complete Active Directory hardening project timeline, divided into 5 distinct phases over a 90-day period.

---

## Timeline Overview

| Phase | Duration | Timeline | Focus Area |
|-------|----------|----------|------------|
| **Phase 1** | 7 days | Days 1-7 | Critical/Immediate Actions |
| **Phase 2** | 7 days | Days 8-14 | High Priority Security Controls |
| **Phase 3** | 16 days | Days 15-30 | Medium Priority Hardening |
| **Phase 4** | 60 days | Days 31-90 | Additional Enhancements |
| **Phase 5** | Ongoing | Post Day 90 | Continuous Monitoring |

---

## Phase 1: Critical Actions (Days 1-7)

**Objective:** Address immediate security risks that could lead to domain compromise

### Tasks and Timeline

```
Week 1 (Days 1-7)
├─ Day 1-2: Initial Assessment & Planning
│  ├─ Run PingCastle security assessment
│  ├─ Review findings and prioritize risks
│  └─ Establish change management process
│
├─ Day 2-3: Print Spooler Mitigation
│  ├─ Audit DC printing requirements (none expected)
│  ├─ Disable Print Spooler on DC01 and DC02
│  └─ Verify service disabled and stopped
│
├─ Day 3-5: Password Policy Enhancement
│  ├─ Review current password policy settings
│  ├─ Notify users 48 hours in advance
│  ├─ Update minimum password length to 12 characters
│  ├─ Set password history to 24 passwords
│  └─ Verify policy application via GPO
│
└─ Day 5-7: NTLMv1 Ban (Audit Phase Begins)
   ├─ Enable NTLM auditing on all DCs
   ├─ Monitor authentication logs for 48-72 hours
   ├─ Identify legacy NTLM dependencies
   └─ Prepare for enforcement (Phase 2)
```

**Deliverables:**
- Print Spooler disabled on all DCs
- Password policy updated to 12-character minimum
- NTLM audit data collected for Phase 2 enforcement

---

## Phase 2: High Priority Controls (Days 8-14)

**Objective:** Deploy critical security controls and enforce authentication hardening

### Tasks and Timeline

```
Week 2 (Days 8-14)
├─ Day 8-10: NTLMv1 Ban Enforcement
│  ├─ Review NTLM audit logs from Phase 1
│  ├─ Contact application owners for legacy dependencies
│  ├─ Set LM Authentication Level to 5 (NTLMv2 only)
│  └─ Monitor for authentication failures
│
├─ Day 10-12: Windows LAPS Deployment (Pilot)
│  ├─ Create pilot OU with 3-5 test workstations
│  ├─ Configure LAPS GPO settings
│  │  ├─ Password complexity: Level 4
│  │  ├─ Password length: 14 characters
│  │  └─ Rotation interval: 30 days
│  ├─ Test password retrieval and rotation
│  └─ Document pilot results
│
└─ Day 12-14: RPC Coercion Mitigation
   ├─ Enable NTLM outbound auditing on DCs (Value 1)
   ├─ Monitor for 48 hours
   ├─ Block NTLM outbound traffic (Value 2)
   └─ Verify DC authentication restrictions
```

**Deliverables:**
- NTLMv1 fully banned domain-wide
- LAPS successfully piloted on test systems
- RPC coercion attacks mitigated via NTLM restrictions

---

## Phase 3: Medium Priority Hardening (Days 15-30)

**Objective:** Implement protocol security and comprehensive audit controls

### Tasks and Timeline

```
Weeks 3-4 (Days 15-30)
├─ Day 15-18: LDAP Security Hardening
│  ├─ LDAP Signing Requirement
│  │  ├─ Enable LDAP diagnostics (Event 2889)
│  │  ├─ Monitor unsigned binds for 48 hours
│  │  ├─ Set LDAPServerIntegrity = 2
│  │  └─ Verify LDAP signing enforcement
│  │
│  └─ LDAPS Channel Binding
│     ├─ Monitor Events 3039/3040
│     ├─ Set LdapEnforceChannelBinding = 1
│     └─ Test LDAPS client compatibility
│
├─ Day 18-22: Domain Controller Audit Baseline
│  ├─ Check SIEM log ingestion capacity
│  ├─ Apply Advanced Audit Policy GPO
│  │  ├─ Credential Validation
│  │  ├─ Kerberos Authentication Service
│  │  ├─ User Account Management
│  │  ├─ Security Group Management
│  │  └─ Directory Service Changes
│  └─ Verify audit events in Security log
│
├─ Day 22-25: ADCS Web Enrollment Security
│  ├─ Review IIS logs for HTTP certsrv usage
│  ├─ Notify users of HTTPS-only requirement
│  ├─ Remove HTTP binding on CA01
│  └─ Test HTTPS-only certificate enrollment
│
├─ Day 25-27: AD Sites & Subnets Configuration
│  ├─ Document current DC IP addresses
│  ├─ Add missing subnet 192.168.51.0/24
│  ├─ Verify site association
│  └─ Test replication topology
│
└─ Day 27-30: Privileged Account Protection
   ├─ Identify admin accounts without delegation protection
   ├─ Set "Account is sensitive and cannot be delegated" flag
   ├─ Add eligible accounts to Protected Users group
   ├─ Empty Schema Admins group
   └─ Configure UNC Hardened Paths GPO
```

**Deliverables:**
- LDAP signing and channel binding enforced
- Advanced audit policy active on all DCs
- ADCS web enrollment secured (HTTPS only)
- AD Sites properly configured
- Privileged accounts hardened

---

## Phase 4: Additional Security Enhancements (Days 31-90)

**Objective:** Deploy advanced security features and complete defense-in-depth strategy

### Tasks and Timeline

```
Months 2-3 (Days 31-90)
├─ Day 31-40: Windows LAPS Domain-Wide Rollout
│  ├─ Expand LAPS to IT workstations OU
│  ├─ Monitor password rotation success rate
│  ├─ Deploy to all domain workstations
│  ├─ Train helpdesk on LAPS password retrieval
│  └─ Document LAPS delegation model
│
├─ Day 40-50: Group Managed Service Accounts (gMSA)
│  ├─ Create KDS root key (-EffectiveTime 10 hours ago)
│  ├─ Identify service accounts to migrate
│  ├─ Create gMSA for pilot service
│  ├─ Test gMSA authentication and SPN resolution
│  └─ Migrate 2-3 service accounts to gMSA
│
├─ Day 50-60: Name Resolution Protocol Security
│  ├─ Disable LLMNR
│  │  ├─ Test in pilot OU for 7 days
│  │  ├─ Monitor for name resolution failures
│  │  ├─ Apply domain-wide via GPO
│  │  └─ Verify EnableMulticast = 0
│  │
│  └─ Disable NetBIOS over TCP/IP
│     ├─ Test in pilot OU for 7 days
│     ├─ Create GPO startup script
│     ├─ Deploy domain-wide
│     └─ Verify TcpipNetbiosOptions = 2
│
├─ Day 60-70: Secure Remote Access Protocols
│  ├─ RDP Hardening
│  │  ├─ Enable Network Level Authentication (NLA)
│  │  ├─ Set encryption to High (Level 3)
│  │  ├─ Enable Restricted Admin Mode
│  │  └─ Configure firewall IP restrictions
│  │
│  └─ WinRM Hardening
│     ├─ Remove HTTP listeners (port 5985)
│     ├─ Configure HTTPS listeners with certificates
│     ├─ Restrict TrustedHosts (no wildcard *)
│     └─ Enable WinRM operational logging
│
├─ Day 70-80: PowerShell Security & Logging
│  ├─ Enable Script Block Logging
│  ├─ Enable Module Logging
│  ├─ Enable Transcription (optional, high volume)
│  ├─ Configure SIEM to ingest PowerShell logs
│  └─ Test log volume and SIEM capacity
│
└─ Day 80-90: Final Hardening & Documentation
   ├─ Enable AD Recycle Bin (irreversible)
   ├─ Deploy Protected Users group strategy
   ├─ Implement administrative tier model
   ├─ Create runbooks for each security control
   ├─ Document rollback procedures
   └─ Conduct final PingCastle assessment
```

**Deliverables:**
- LAPS deployed domain-wide
- gMSA implemented for service accounts
- LLMNR and NetBIOS disabled
- RDP and WinRM hardened
- PowerShell logging active
- AD Recycle Bin enabled
- Complete documentation and runbooks

---

## Phase 5: Continuous Monitoring (Post Day 90)

**Objective:** Maintain security posture and detect anomalies

### Ongoing Activities

```
Continuous Operations
├─ Daily Monitoring
│  ├─ Review SIEM alerts for authentication anomalies
│  ├─ Monitor failed logon attempts (Event 4625)
│  ├─ Check for new privileged group memberships
│  └─ Review PowerShell suspicious activity logs
│
├─ Weekly Tasks
│  ├─ Review LAPS password rotation success rate
│  ├─ Audit RDP/WinRM access logs
│  ├─ Check for GPO changes (Event 5136)
│  └─ Verify domain controller health
│
├─ Monthly Tasks
│  ├─ Review privileged account usage
│  ├─ Audit Schema Admins group (should be empty)
│  ├─ Test backup and recovery procedures
│  └─ Update security baselines as needed
│
└─ Quarterly Tasks
   ├─ Run PingCastle security assessment
   ├─ Review and update GPO security settings
   ├─ Conduct privileged access review
   ├─ Test incident response playbooks
   └─ Update security documentation
```

**Deliverables:**
- Quarterly PingCastle assessment reports
- Monthly privileged access review reports
- Incident response readiness
- Up-to-date security documentation

---

## Visual Gantt Chart

```
Project Timeline: Active Directory Hardening (90 Days)

Phase 1 (Days 1-7): Critical Actions
|████████|
 ├─ Print Spooler Disable
 ├─ Password Policy Update
 └─ NTLM Audit Mode

Phase 2 (Days 8-14): High Priority
        |████████|
         ├─ NTLMv1 Ban
         ├─ LAPS Pilot
         └─ RPC Coercion Fix

Phase 3 (Days 15-30): Medium Priority
                |████████████████████|
                 ├─ LDAP Security
                 ├─ DC Audit Baseline
                 ├─ ADCS HTTPS
                 └─ Privilege Hardening

Phase 4 (Days 31-90): Enhancements
                                    |████████████████████████████████████████████████|
                                     ├─ LAPS Rollout
                                     ├─ gMSA Deployment
                                     ├─ Protocol Disable (LLMNR/NetBIOS)
                                     ├─ RDP/WinRM Hardening
                                     └─ PowerShell Logging

Phase 5 (Day 91+): Continuous Monitoring
                                                                                    |████████████...
                                                                                     └─ Ongoing Operations

Timeline: |----|----|----|----|----|----|----|----|----|----|----|----|----|----|
Days:      0   7   14   21   28   35   42   49   56   63   70   77   84   91  ...
```

---

## Critical Dependencies

### Phase 1 → Phase 2
- NTLM audit data (Phase 1) required before enforcement (Phase 2)
- Password policy change notification period

### Phase 2 → Phase 3
- LAPS pilot success required before domain rollout
- NTLM restrictions validated before LDAP hardening

### Phase 3 → Phase 4
- Audit baseline active before protocol disablement
- LDAP security confirmed before name resolution changes

---

## Risk Mitigation Strategy

| Risk | Mitigation | Timeline Impact |
|------|------------|-----------------|
| **Application compatibility issues** | Use audit mode before enforcement (48-72 hours) | +3 days per protocol change |
| **User communication delays** | Notify 48 hours in advance for policy changes | Built into Phase 1 |
| **SIEM capacity constraints** | Validate log ingestion before audit baseline | Planned in Phase 3 |
| **Legacy system dependencies** | Pilot testing in isolated OUs first | Built into all phases |
| **Rollback requirements** | Document rollback for each change | Ongoing documentation |

---

## Success Metrics

### Phase Completion Criteria

**Phase 1:**
- [ ] Print Spooler disabled on DC01 and DC02
- [ ] Minimum password length = 12 characters
- [ ] NTLM audit data collected for 72 hours

**Phase 2:**
- [ ] LmCompatibilityLevel = 5 on all systems
- [ ] LAPS pilot successful (3+ systems)
- [ ] RestrictSendingNTLMTraffic = 2 on DCs

**Phase 3:**
- [ ] LDAPServerIntegrity = 2
- [ ] Advanced Audit Policy GPO applied
- [ ] ADCS HTTP binding removed
- [ ] Schema Admins group empty

**Phase 4:**
- [ ] LAPS deployed to 100% of workstations
- [ ] 3+ service accounts migrated to gMSA
- [ ] LLMNR disabled (EnableMulticast = 0)
- [ ] WinRM HTTP listeners removed

**Phase 5:**
- [ ] PingCastle score improved from 77/100 to <50/100
- [ ] Zero HIGH risk findings
- [ ] SIEM monitoring active for all critical events

---

## Change Management Integration

All changes follow this approval workflow:

1. **Planning Phase** (Days 1-3 before change)
   - Document change request with business justification
   - Identify affected systems and dependencies
   - Prepare rollback procedure

2. **Testing Phase** (Pilot/Audit Mode)
   - Deploy to pilot OU or enable audit mode
   - Monitor for 48-72 hours
   - Collect compatibility data

3. **Approval Phase** (24 hours before change)
   - Present pilot results to change advisory board
   - Obtain approval from stakeholders
   - Schedule maintenance window if needed

4. **Implementation Phase**
   - Execute change during approved window
   - Monitor authentication/application logs
   - Document implementation notes

5. **Validation Phase** (24-48 hours post-change)
   - Verify remediation success
   - Confirm no service disruptions
   - Close change request

---

## Resource Allocation

| Phase | Required Resources | Estimated Hours |
|-------|-------------------|-----------------|
| **Phase 1** | 1 AD Admin, 1 Security Analyst | 16 hours |
| **Phase 2** | 1 AD Admin, 1 Security Analyst, Helpdesk Coordinator | 24 hours |
| **Phase 3** | 1 AD Admin, 1 Security Analyst, PKI Admin, SIEM Admin | 40 hours |
| **Phase 4** | 1 AD Admin, 1 Security Analyst, Helpdesk Team | 80 hours |
| **Phase 5** | 0.25 FTE Security Analyst (ongoing) | 10 hours/week |

**Total Project Effort:** ~160 hours over 90 days + ongoing monitoring

---

[← Back to Main](../README.md)
