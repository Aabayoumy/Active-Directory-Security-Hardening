# Active Directory Security Hardening
## Mitigating Risks from Default Configurations

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Windows Server 2022](https://img.shields.io/badge/Windows%20Server-2022-blue)](https://www.microsoft.com/en-us/windows-server)
[![Active Directory](https://img.shields.io/badge/Active%20Directory-Hardening-green)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)

> A comprehensive cybersecurity diploma project focusing on identifying and mitigating security risks in default Active Directory configurations using automated assessment tools and industry best practices.

**Author:** Ahmed Bayoumy  
**Supervisor:** Prof. Mahmoud Elkholy  
**Date:** December 2025  
**Assessment Tool:** Netwrix PingCastle 3.4.1.38

---

## 📋 Table of Contents

- [Overview](#overview)
- [Project Objectives](#project-objectives)
- [Methodology](#methodology)
- [Key Findings](#key-findings)
- [Documentation Structure](#documentation-structure)
- [Quick Start](#quick-start)
- [Technologies Used](#technologies-used)
- [Compliance Frameworks](#compliance-frameworks)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

Default Active Directory installations, particularly Windows Server 2022 (November 2025 build), often retain legacy protocols and permissive settings for backward compatibility. This creates a broad attack surface that adversaries can exploit for lateral movement, privilege escalation, and domain compromise.

This project demonstrates a **Detection-First** approach to Active Directory hardening:
- ✅ **No simulated attacks** - Configuration assessment only
- ✅ **Automated risk identification** - Using PingCastle tool
- ✅ **Audit-before-enforcement** - Business continuity focused
- ✅ **Practical PowerShell implementation** - Copy-paste ready scripts
- ✅ **ISO 27001 & MITRE ATT&CK aligned** - Compliance-ready

### What Makes This Different?

Unlike standard hardening guides that advocate for immediate enforcement, this project proposes a **"Detection and Audit"** methodology. By using native tools like Group Policy Objects (GPO) and Event Viewer to identify active dependencies before enforcing restrictions, organizations can achieve a hardened security posture without unintended service outages.

---

## 🎯 Project Objectives

1. **Identify Security Risks** - Assess default AD configurations using automated tools
2. **Analyze Insecure Protocols** - Identify usage of NTLM, unsigned LDAP, and legacy protocols
3. **Recommend Mitigations** - Provide step-by-step remediation with PowerShell scripts
4. **Additional Hardening** - Implement security enhancements (LAPS, secure RDP/WinRM, auditing)
5. **Maintain Business Continuity** - Ensure no disruption through audit-first approach

---

## 🔬 Methodology

### Assessment Approach

This is a **configuration assessment and hardening project**, NOT penetration testing:

```
┌─────────────────┐
│   Detection     │  PowerShell commands to verify vulnerabilities
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Audit Mode    │  Enable logging for 48-72 hours
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Impact Analysis │  Review dependencies and business impact
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Mitigation    │  Apply hardening with PowerShell/GPO
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Verification   │  Confirm successful implementation
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Rollback      │  Documented procedures if needed
└─────────────────┘
```

### Tools Used

- **PingCastle** - Automated AD security assessment
- **PowerShell** - Configuration detection and remediation
- **Group Policy** - Enterprise-wide security enforcement
- **Event Viewer** - Dependency identification and monitoring

---

## 🔍 Key Findings

Assessment of default Windows Server 2022 AD forest revealed:

### Risk Summary
- **Overall Risk Score:** 77/100 (HIGH)
- **Total Findings:** 14 security issues
  - 🔴 **HIGH Risk:** 5 findings (36%) - Immediate action required
  - 🟡 **MEDIUM Risk:** 8 findings (57%) - Action within 30 days
  - 🟢 **LOW Risk:** 1 finding (7%) - Best practice recommendation

### Critical Vulnerabilities

| Finding | Risk Level | MITRE ATT&CK | ISO 27001 |
|---------|-----------|--------------|-----------|
| Weak Password Policy (7 chars min) | 🔴 HIGH | T1201 | 5.17, 5.18 |
| NTLMv1/LM Authentication Enabled | 🔴 HIGH | T1557.001 | 8.5 |
| LAPS Not Deployed | 🔴 HIGH | T1078.003 | 5.17, 5.18 |
| Print Spooler on DCs (PrintNightmare) | 🔴 HIGH | T1187 | 8.8 |
| RPC Coercion (PetitPotam) | 🔴 HIGH | T1187 | 8.8 |

---

## 📚 Documentation Structure

### Main Chapters

1. **[Introduction](chapters/01-introduction.md)** - Project background, scope, and objectives
2. **[Literature Review](chapters/02-literature-review.md)** - Background on AD security challenges
3. **[Lab Environment](chapters/03-lab-environment.md)** - Infrastructure setup and design
4. **[Security Assessment](chapters/04-security-assessment.md)** - PingCastle findings and risk analysis
5. **[Protocol Mitigation](chapters/05-protocol-remediation.md)** - Hardening insecure protocols (NTLM, LDAP, RPC, LLMNR)
6. **[Configuration Hardening](chapters/06-configuration-hardening.md)** - System configs and security features
7. **[Additional Hardening Actions](chapters/07-additional-hardening-actions.md)** - RDP, WinRM, and gMSA implementations
8. **[Results and Analysis](chapters/08-results-analysis.md)** - Analysis and security posture improvement
9. **[Conclusion](chapters/09-conclusion.md)** - Summary and future work
10. **[References](chapters/10-references.md)** - Citations and resources

### Additional Hardening

- **[RDP & WinRM Hardening Guide](additional-hardening/rdp-winrm-guide.md)** - Detailed implementation guide
- **[gMSA Deployment Guide](additional-hardening/gmsa-guide.md)** - Group Managed Service Accounts guide

### Appendices

- **[Appendix A: Gantt Chart](appendices/appendix-a-gantt-chart.md)** - Project timeline
- **[Appendix D: PowerShell Scripts](appendices/appendix-d-powershell-scripts.md)** - Complete script library
- **[Appendix E: GPO Templates](appendices/appendix-e-gpo-templates.md)** - Group Policy configurations
- **[Appendix F: Lab Topology](appendices/appendix-f-lab-topology.md)** - Lab network topology
- **[Appendix G: Compliance Mapping](appendices/appendix-g-compliance-mapping.md)** - Compliance mapping
- **[Appendix H: VAPT Report](appendices/appendix-h-vapt-report.md)** - Complete assessment report

### Scripts & Resources

- **[Detection Scripts](scripts/detection/)** - PowerShell commands to verify vulnerabilities
- **[Audit Scripts](scripts/audit/)** - Enable monitoring before enforcement
- **[Mitigation Scripts](scripts/mitigation/)** - Remediation implementations
- **[Verification Scripts](scripts/verification/)** - Validate successful changes
- **[Rollback Scripts](scripts/rollback/)** - Revert procedures

---

## 🚀 Quick Start

### Prerequisites

- Windows Server 2022 (or 2019 with updates)
- Active Directory Domain Services role
- Domain Admin privileges
- PowerShell 5.1 or later
- PingCastle tool ([Download](https://www.pingcastle.com/download/))

### Running the Assessment

```powershell
# 1. Download PingCastle
# Visit: https://www.pingcastle.com/download/

# 2. Run assessment
.\PingCastle.exe --healthcheck --server dc01.contoso.com

# 3. Review report
# Open: ad_hc_contoso.com_<date>.html
```

### Implementing Remediations

Follow the phased approach documented in:
- [Phase 1: Critical (0-7 days)](chapters/05-protocol-remediation.md#phase-1-critical-protocol-mitigations-0-7-days)
- [Phase 2: High Priority (7-14 days)](chapters/06-configuration-hardening.md#phase-2-high-priority-configurations-7-14-days)
- [Phase 3: Medium Priority (14-30 days)](chapters/05-protocol-remediation.md#phase-3-ldap-protocol-security-14-30-days)
- [Phase 4: Additional Hardening (30-90 days)](chapters/06-configuration-hardening.md#phase-4-additional-security-features-30-90-days)

**⚠️ Important:** Always enable audit mode first before enforcement! See [Detection-First Methodology](chapters/08-discussion.md#detection-first-methodology).

---

## 🛠️ Technologies Used

| Technology | Purpose |
|------------|---------|
| **Windows Server 2022** | Domain Controllers (DC01, DC02) |
| **Active Directory** | Identity management infrastructure |
| **Windows LAPS** | Local admin password management (native) |
| **Group Policy** | Enterprise configuration management |
| **PowerShell 5.1+** | Automation and remediation |
| **PingCastle** | Automated security assessment |
| **ADCS (PKI)** | Certificate services (CA01) |
| **Windows 11** | Client workstation testing |

---

## 📋 Compliance Frameworks

This project aligns with multiple security frameworks:

### ISO/IEC 27001:2022

Controls addressed:
- **5.17** - Authentication Information
- **5.18** - Access Rights
- **8.2** - Privileged Access Rights
- **8.5** - Secure Authentication
- **8.8** - Management of Technical Vulnerabilities
- **8.15** - Logging
- **8.24** - Use of Cryptography

### MITRE ATT&CK Enterprise

Techniques mitigated:
- **T1078.003** - Valid Accounts: Local Accounts
- **T1187** - Forced Authentication
- **T1201** - Password Policy Discovery
- **T1557** - Adversary-in-the-Middle
- **T1557.001** - LLMNR/NBT-NS Poisoning

### Additional Standards

- ✅ NIST Cybersecurity Framework
- ✅ CIS Critical Security Controls
- ✅ PCI DSS (authentication requirements)
- ✅ GDPR (technical measures)

---

## 📊 Project Statistics

- **Total Pages:** ~165-205 pages (when exported)
- **PowerShell Scripts:** 80+ detection/audit/mitigation/verification commands
- **Findings Addressed:** 14 security issues
- **Remediation Phases:** 4 phased implementation stages
- **Risk Reduction:** From 77/100 to target <30/100
- **Lab Components:** 2 DCs + 1 CA + 1 Workstation

---

## 💡 Key Features

### Detection-First Approach
- ✅ No business disruption
- ✅ Identify dependencies before enforcement
- ✅ 48-72 hour audit periods
- ✅ Rollback procedures for all changes

### Complete PowerShell Coverage
- 🔍 **Detection** scripts to verify issues
- 📊 **Audit** scripts to enable monitoring
- 🔧 **Mitigation** scripts for remediation
- ✅ **Verification** scripts to confirm success
- ↩️ **Rollback** scripts for safety

### Production-Ready
- Real-world tested configurations
- Change management integration
- Impact assessment methodology
- Stakeholder communication templates

---

## 🤝 Contributing

This is an academic diploma project, but feedback and suggestions are welcome!

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/improvement`)
3. **Commit your changes** (`git commit -am 'Add improvement'`)
4. **Push to the branch** (`git push origin feature/improvement`)
5. **Create a Pull Request**

### Areas for Contribution

- Additional PowerShell automation scripts
- Alternative GPO configurations
- SIEM integration examples
- Hybrid/Azure AD scenarios
- Translation to other languages
- Additional diagrams and visualizations

---

## 📖 Documentation Guidelines

All documentation follows:
- ✅ Markdown formatting (GitHub flavored)
- ✅ Clear code block syntax highlighting
- ✅ Consistent heading structure
- ✅ Internal linking between documents
- ✅ PowerShell best practices
- ✅ Security-first recommendations

---

## ⚠️ Disclaimer

This project is for **educational and professional development purposes**. 

**Important Notes:**
- Always test in a lab environment first
- Obtain proper authorization before implementation
- Follow your organization's change management procedures
- Backup configurations before making changes
- Review impact on legacy applications
- Some settings may not suit all environments

The authors and contributors are not responsible for any damage or issues resulting from implementing these configurations. Use at your own risk.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**MIT License Summary:**
- ✅ Commercial use
- ✅ Modification
- ✅ Distribution
- ✅ Private use
- ❌ Liability
- ❌ Warranty

---

## 📞 Contact & Support

**Author:** Ahmed Bayoumy  
**GitHub:** [@aabayoumy](https://github.com/aabayoumy)  
**Project Link:** [Active-Directory-Security-Hardening](https://github.com/aabayoumy/Active-Directory-Security-Hardening)

### Acknowledgments

- **Supervisor:** Prof. Mahmoud Elkholy - For invaluable guidance and support
- **PingCastle Team** - For the excellent AD assessment tool
- **Microsoft** - For Windows LAPS and security documentation
- **Security Community** - For continuous research and sharing

---

## 🔖 References

Key resources used in this project:

- Microsoft Security Baselines for Windows Server 2022
- [Microsoft Windows LAPS Documentation](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [PingCastle Documentation](https://www.pingcastle.com/documentation/)
- [ISO/IEC 27001:2022 Standard](https://www.iso.org/standard/27001)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [CIS Benchmarks for Windows Server](https://www.cisecurity.org/benchmark/microsoft_windows_server)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

## 📈 Project Timeline

```
Week 1-2:   Research & Lab Documentation
Week 3-4:   Security Control Analysis
Week 5-7:   Vulnerability Detection & Mitigation Modeling
Week 8-9:   Auditing & Impact Testing
Week 10-12: Final VAPT Reporting & Documentation
```

Detailed Gantt chart: [Appendix A](appendices/appendix-a-gantt-chart.md)

---

## 🌟 Star History

If you find this project useful, please consider giving it a ⭐!

---

**Last Updated:** February 27, 2026  
**Version:** 3.0  
**Status:** Documentation Complete

---

*This project demonstrates practical Active Directory hardening skills for cybersecurity professionals, system administrators, and security researchers. Perfect for portfolio demonstration, academic reference, or production implementation planning.*

---

## Resources

- Active Directory Domain Services overview: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview
- Windows Server security baselines: https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines
- Windows LAPS overview: https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview
