# Chapter 7: Results and Analysis

[← Previous: Configuration Hardening and Security Enhancements](06-configuration-hardening.md) | [Next: Conclusion and Future Work →](08-conclusion.md)

---

## Chapter Overview

This chapter analyzes the results of implementing the security hardening measures detailed in Chapters 5 and 6. It presents the security improvements achieved, discusses the effectiveness of the detection-first methodology, and provides insights into challenges encountered and lessons learned.

---

## 7.1 Security Posture Improvement

### 7.1.1 Risk Reduction Summary

The comprehensive hardening implementation addressed all 14 findings identified in the PingCastle assessment:

| Risk Level | Findings Identified | Findings Remediated | Remediation Rate |
|------------|-------------------|-------------------|------------------|
| HIGH | 5 | 5 | 100% |
| MEDIUM | 8 | 8 | 100% |
| LOW | 1 | 1 | 100% |
| **Total** | **14** | **14** | **100%** |

**Before Hardening:**
- **Domain Health Score:** 77/100 (HIGH risk)
- **Critical Vulnerabilities:** 5 HIGH-risk findings requiring immediate action
- **Security Gaps:** Legacy protocol support, weak configurations, missing security features

**After Hardening:**
- **Projected Domain Health Score:** 90-95/100 (Excellent-Good range)
- **Critical Vulnerabilities:** 0 HIGH-risk findings remaining
- **Security Posture:** Aligned with ISO 27001:2022 and MITRE ATT&CK best practices

### 7.1.2 Remediation Breakdown by Category

**Authentication & Protocol Security:**
- ✓ NTLMv1/LM authentication disabled (enforced NTLMv2 minimum)
- ✓ NTLM outbound traffic blocked from Domain Controllers
- ✓ LDAP signing required for all directory queries
- ✓ LDAPS channel binding enforced
- ✓ LLMNR disabled (name resolution poisoning prevented)
- ✓ NetBIOS over TCP/IP disabled

**Privileged Access Management:**
- ✓ Password policy strengthened (12-character minimum)
- ✓ Windows LAPS deployed for local administrator passwords
- ✓ Admin accounts protected from delegation
- ✓ Schema Admins group emptied (JIT access model)
- ✓ Protected Users group ready for Tier 0 admins

**Service & Configuration Hardening:**
- ✓ Print Spooler disabled on Domain Controllers
- ✓ RPC coercion attacks mitigated
- ✓ ADCS web enrollment migrated to HTTPS-only
- ✓ UNC hardened paths configured for SYSVOL/NETLOGON

**Remote Access Security:**
- ✓ RDP hardened (NLA enabled, High encryption, Restricted Admin mode)
- ✓ WinRM migrated to HTTPS-only
- ✓ Firewall rules restricted to authorized networks

**Audit & Monitoring:**
- ✓ Advanced audit policies implemented
- ✓ PowerShell script block logging enabled
- ✓ Critical security events monitored

**Directory Resilience:**
- ✓ AD Recycle Bin enabled
- ✓ AD Sites and Subnets properly configured
- ✓ Group Managed Service Accounts (gMSA) framework established

---

## 7.2 Detection-First Methodology Effectiveness

### 7.2.1 Audit Mode Success Metrics

The audit-first approach proved highly effective in preventing business disruptions:

**NTLM Restrictions:**
- **Audit Period:** 72 hours
- **Finding:** 3 legacy applications using NTLM identified
- **Action:** Application owners contacted, updated to Kerberos
- **Outcome:** Zero business disruption during enforcement

**LDAP Signing Enforcement:**
- **Audit Period:** 48 hours
- **Finding:** 1 network device (printer) using unsigned LDAP
- **Action:** Printer firmware updated to support LDAP signing
- **Outcome:** Smooth transition with no authentication failures

**LLMNR/NetBIOS Disablement:**
- **Audit Period:** 7 days (pilot OU)
- **Finding:** No name resolution failures detected
- **Action:** Deployed domain-wide with confidence
- **Outcome:** No helpdesk tickets related to name resolution

**Print Spooler Disablement:**
- **Audit Period:** Immediate (DCs should never require printing)
- **Finding:** No print jobs or printers on Domain Controllers
- **Action:** Immediate disablement
- **Outcome:** Zero impact (as expected)

### 7.2.2 Business Continuity Achievement

**Key Success Metrics:**

| Metric | Target | Achieved | Status |
|--------|--------|----------|--------|
| Zero critical business disruptions | 100% | 100% | ✓ Pass |
| Helpdesk tickets related to hardening | < 5 | 2 | ✓ Pass |
| Rollback events required | 0 | 0 | ✓ Pass |
| Stakeholder approval rate | > 95% | 100% | ✓ Pass |
| Implementation timeline adherence | 90 days | 85 days | ✓ Pass |

**Helpdesk Tickets (2 total):**
1. User unable to connect to RDP after NLA enforcement (user had outdated RDP client - resolved by updating)
2. Password policy change notification (user required assistance setting new 12-character password - expected)

**No Rollbacks Required:**
- All changes successfully implemented without need for rollback
- Audit mode effectively identified issues before enforcement
- Pilot OU testing validated configurations before domain-wide deployment

---

## 7.3 Framework Compliance Achievements

### 7.3.1 ISO/IEC 27001:2022 Control Coverage

**Before Hardening:**

| Control Category | Controls Addressed | Controls Not Addressed | Coverage |
|-----------------|-------------------|----------------------|----------|
| Organizational (5.x) | 0 | 3 | 0% |
| Technological (8.x) | 1 | 7 | 12.5% |

**After Hardening:**

| Control Category | Controls Addressed | Controls Not Addressed | Coverage |
|-----------------|-------------------|----------------------|----------|
| Organizational (5.x) | 3 | 0 | 100% |
| Technological (8.x) | 8 | 0 | 100% |

**Specific Controls Achieved:**
- ✓ **5.17 (Authentication Information):** Password policy, LAPS, gMSA
- ✓ **5.18 (Access Rights):** Privileged account management, delegation controls
- ✓ **5.34 (Privacy/PII Protection):** Audit logging, access controls
- ✓ **8.2 (Privileged Access Rights):** Admin account hardening, tiering readiness
- ✓ **8.5 (Secure Authentication):** NTLM restrictions, Kerberos enforcement
- ✓ **8.8 (Technical Vulnerabilities):** Print Spooler, RPC coercion mitigated
- ✓ **8.13 (Information Backup):** AD Recycle Bin enabled
- ✓ **8.15 (Logging):** Advanced audit policies, PowerShell logging
- ✓ **8.24 (Cryptography):** LDAPS, HTTPS, encrypted RDP/WinRM

### 7.3.2 MITRE ATT&CK Technique Mitigation

**Adversary Techniques Mitigated:**

| Technique ID | Technique Name | Mitigation Implemented | Effectiveness |
|--------------|----------------|----------------------|---------------|
| T1078.003 | Valid Accounts: Local Accounts | LAPS deployment | High |
| T1187 | Forced Authentication | Print Spooler disabled, RPC restricted | High |
| T1201 | Password Policy Discovery | Strong password policy | Medium |
| T1550.002 | Pass the Hash | NTLM restrictions, Protected Users | High |
| T1557 | Adversary-in-the-Middle | LDAP signing, LDAPS binding | High |
| T1557.001 | LLMNR/NBT-NS Poisoning | LLMNR/NetBIOS disabled | High |

**Overall ATT&CK Coverage:**
- **Before:** Limited defensive coverage, vulnerable to common credential access techniques
- **After:** Strong defense-in-depth against credential theft, lateral movement, and privilege escalation

---

## 7.4 Challenges and Solutions

### 7.4.1 Technical Challenges

**Challenge 1: Legacy Application NTLM Dependencies**

**Issue:** Three applications discovered using NTLM during audit period.

**Solution:**
- Identified applications via Event ID 4624 (NTLM logon events)
- Contacted application owners
- Updated applications to support Kerberos authentication
- Tested in pilot environment before domain-wide enforcement
- Documented exceptions for one legacy application (decommission planned)

**Lesson:** Audit mode is CRITICAL before enforcing NTLM restrictions.

---

**Challenge 2: HTTPS Certificate Deployment for WinRM**

**Issue:** Many servers lacked certificates with Server Authentication EKU for WinRM HTTPS.

**Solution:**
- Leveraged Enterprise CA (CA01) to issue certificates via autoenrollment
- Created certificate template with Server Authentication EKU
- Configured GPO for automatic certificate enrollment
- Verified certificates deployed before removing HTTP listeners

**Lesson:** Certificate infrastructure must be in place before enforcing HTTPS-only protocols.

---

**Challenge 3: PowerShell Logging Storage Requirements**

**Issue:** PowerShell script block logging generated 300-400 MB/day per server.

**Solution:**
- Increased Event Log maximum size to 2 GB
- Configured event log forwarding to centralized SIEM
- Implemented log retention policy (90 days local, 1 year in SIEM)
- Monitored disk space usage on Domain Controllers

**Lesson:** Plan for increased storage requirements when enabling comprehensive logging.

---

### 7.4.2 Organizational Challenges

**Challenge 1: Stakeholder Communication**

**Issue:** Initial resistance to password policy change (12-character minimum).

**Solution:**
- Presented risk data from PingCastle assessment
- Explained business impact of weak passwords
- Provided 48-hour advance notice to users
- Prepared helpdesk with FAQs and password reset assistance
- Implemented change during low-activity period

**Lesson:** Clear communication and business justification are essential for user-impacting changes.

---

**Challenge 2: Change Management Approval Delays**

**Issue:** Some hardening changes required multiple approval cycles.

**Solution:**
- Bundled related changes into single change requests (e.g., all LDAP security changes)
- Provided detailed rollback procedures in change requests
- Demonstrated successful pilot OU testing results
- Engaged executive sponsor for high-priority changes

**Lesson:** Comprehensive change documentation accelerates approval process.

---

## 7.5 Performance Impact Analysis

### 7.5.1 System Performance

**Domain Controller CPU Usage:**

| Metric | Before Hardening | After Hardening | Change |
|--------|-----------------|----------------|--------|
| Average CPU | 15% | 17% | +2% |
| Peak CPU | 35% | 40% | +5% |
| Impact | Baseline | Acceptable | Minimal |

**Analysis:** LDAP signing and advanced audit policies increased CPU usage slightly, within acceptable thresholds.

---

**Domain Controller Memory Usage:**

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| Memory Used | 4.2 GB / 8 GB | 4.5 GB / 8 GB | +300 MB |
| Impact | 53% | 56% | +3% |

**Analysis:** Memory usage increase minimal, well within capacity.

---

**Authentication Performance:**

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| Avg Logon Time | 2.3 seconds | 2.5 seconds | +0.2s |
| Impact | Baseline | Acceptable | Negligible |

**Analysis:** LDAP signing and Kerberos-only authentication added minimal latency. User experience unaffected.

---

### 7.5.2 Network Traffic Analysis

**LDAP Traffic:**
- Signed LDAP adds ~15% overhead compared to unsigned
- Encrypted LDAPS (port 636) adds ~20% overhead vs. plaintext LDAP (port 389)
- Impact: Negligible on modern networks (overhead measured in kilobytes)

**RDP Traffic:**
- High encryption mode adds ~5% overhead
- NLA reduces overall traffic by authenticating before session establishment

**Overall Network Impact:** < 1% increase in overall network traffic

---

## 7.6 Security Monitoring and Visibility

### 7.6.1 Enhanced Security Event Collection

**Before Hardening:**
- **Daily Security Events:** ~5,000 events/day per DC
- **Visibility:** Limited to basic logon/logoff events
- **SIEM Integration:** None

**After Hardening:**
- **Daily Security Events:** ~18,000 events/day per DC (3.6x increase)
- **Visibility:** Comprehensive coverage of authentication, privilege use, directory changes
- **SIEM Integration:** Event forwarding configured for future integration

**Critical Events Now Monitored:**

| Event Category | Event IDs | Value |
|----------------|-----------|-------|
| Kerberos Authentication | 4768, 4769, 4771 | Detect authentication issues |
| Directory Service Changes | 5136, 5137, 5138, 5139 | Track AD object modifications |
| Privileged Group Changes | 4728, 4729, 4756, 4757 | Alert on admin group changes |
| NTLM Usage (Post-Restriction) | 8004, 8005, 8006 | Identify remaining NTLM usage |
| PowerShell Execution | 4104 | Detect malicious scripts |

### 7.6.2 Alerting Capabilities

**High-Priority Alerts Configured:**

1. **Schema Admins Group Membership Change** (Event 4728/4729)
   - Immediate alert to security team
   - Should remain empty except during approved schema changes

2. **Failed Logon to Domain Controller** (Event 4625 on DC)
   - Track brute force attempts against DCs
   - Alert on > 10 failures in 5 minutes

3. **NTLM Authentication After Restriction** (Event 8004)
   - Identify unauthorized NTLM usage
   - Should be zero or near-zero after hardening

4. **Unsigned LDAP Bind Attempt** (Event 2887/2888)
   - Detect clients not complying with LDAP signing
   - Alert on any occurrence post-enforcement

5. **PowerShell Suspicious Keywords** (Event 4104)
   - Monitor for commands like: Invoke-Mimikatz, Invoke-Expression (IEX), encoded commands
   - Require manual review

---

## 7.7 Lessons Learned and Best Practices

### 7.7.1 Successful Strategies

**1. Audit-First Approach**
- **Success Factor:** Zero business disruptions during implementation
- **Best Practice:** Always enable audit/logging mode minimum 48-72 hours before enforcement
- **Recommendation:** Extend audit period to 7 days for changes affecting user authentication

**2. Pilot OU Testing**
- **Success Factor:** Identified issues in controlled environment before domain-wide deployment
- **Best Practice:** Use dedicated pilot OU with diverse system types (DC, server, workstation)
- **Recommendation:** Monitor pilot for minimum 7 days, longer for major changes

**3. PowerShell Automation**
- **Success Factor:** Consistent implementation across all systems with verification
- **Best Practice:** Document Detection → Audit → Mitigation → Verification for every change
- **Recommendation:** Maintain version-controlled repository of hardening scripts

**4. Stakeholder Engagement**
- **Success Factor:** 100% approval rate for change requests
- **Best Practice:** Present PingCastle findings and risk data to justify changes
- **Recommendation:** Include application owners in audit phase to identify dependencies

### 7.7.2 Areas for Improvement

**1. Certificate Management**
- **Gap:** Some systems lacked certificates for HTTPS-only protocols
- **Improvement:** Implement certificate autoenrollment before enforcing HTTPS requirements
- **Action:** Deploy certificate templates and GPO autoenrollment at project start

**2. Documentation**
- **Gap:** Initial runbooks lacked detail on troubleshooting common issues
- **Improvement:** Expand troubleshooting guides based on pilot OU findings
- **Action:** Create detailed FAQ for helpdesk before user-impacting changes

**3. SIEM Integration**
- **Gap:** Event log forwarding configured but SIEM not yet deployed
- **Improvement:** Complete SIEM deployment to leverage enhanced audit logs
- **Action:** Prioritize SIEM implementation in Phase 2 of security roadmap

**4. Automated Compliance Monitoring**
- **Gap:** Manual verification of hardening configurations
- **Improvement:** Implement automated compliance checking (PowerShell DSC or similar)
- **Action:** Develop quarterly PingCastle rescans and automated configuration drift detection

---

## Summary

This chapter analyzed the results of the Active Directory hardening implementation:

- **Security Improvement:** 100% of identified findings remediated, projected health score improvement from 77/100 to 90-95/100
- **Business Continuity:** Zero critical disruptions, 2 minor helpdesk tickets, zero rollbacks required
- **Compliance:** Full alignment with ISO 27001:2022 controls and MITRE ATT&CK mitigations
- **Performance:** Minimal impact on system performance (<5% CPU increase, <1% network overhead)
- **Monitoring:** 3.6x increase in security event collection, comprehensive visibility into AD security
- **Methodology:** Audit-first approach proved highly effective in preventing business disruptions

The detection-first methodology successfully balanced security improvement with operational continuity. The next chapter provides conclusions and recommendations for future work.

---

[← Previous: Configuration Hardening and Security Enhancements](06-configuration-hardening.md) | [Next: Conclusion and Future Work →](08-conclusion.md)
