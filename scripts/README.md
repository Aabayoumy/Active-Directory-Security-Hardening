# Active Directory Hardening Scripts

This directory contains PowerShell scripts extracted from the Active Directory Hardening Project documentation. All scripts follow a standardized **Detection → Audit → Mitigation → Verification → Rollback** workflow to ensure safe, auditable implementation of security hardening measures.

## Directory Structure

```
scripts/
├── detection/          # Scripts to detect security vulnerabilities
├── audit/             # Scripts to enable audit/logging modes
├── mitigation/        # Scripts to implement security fixes
├── verification/      # Scripts to verify successful implementation
├── rollback/          # Scripts to rollback changes if needed
└── README.md          # This file
```

## Script Categories

### Detection Scripts (15 scripts)

Detection scripts identify security vulnerabilities and misconfigurations without making changes to the environment.

| Script | Finding | Description | Reference |
|--------|---------|-------------|-----------|
| `Detect-WeakPasswordPolicy.ps1` | H-01 | Checks if minimum password length is below 12 characters | ISO 27001: 5.17, 5.18 |
| `Detect-NTLMv1Authentication.ps1` | H-02 | Detects if NTLMv1/LM authentication is enabled | MITRE: T1557.001 |
| `Detect-LAPSDeployment.ps1` | H-03 | Checks if Windows LAPS is deployed | MITRE: T1078.003 |
| `Detect-PrintSpoolerOnDCs.ps1` | H-04 | Detects Print Spooler service on Domain Controllers | CVE-2021-34527 |
| `Detect-RPCCoercion.ps1` | H-05 | Checks NTLM outbound restrictions (PetitPotam mitigation) | CVE-2021-36942 |
| `Detect-LDAPSigning.ps1` | M-03 | Detects if LDAP signing is required | Section 5.4.1 |
| `Detect-LDAPSChannelBinding.ps1` | M-02 | Detects if LDAPS channel binding is enforced | Section 5.4.2 |
| `Detect-ADCSWebHTTP.ps1` | M-04 | Checks if ADCS Web Enrollment uses HTTP | Section 5.4.3 |
| `Detect-LLMNR.ps1` | - | Detects if LLMNR is enabled | Section 5.5.1 |
| `Detect-NetBIOS.ps1` | - | Detects if NetBIOS over TCP/IP is enabled | Section 5.5.2 |
| `Detect-RDPSecurity.ps1` | - | Checks RDP security configuration (NLA, encryption) | Section 5.6.1 |
| `Detect-WinRMSecurity.ps1` | - | Checks WinRM security (HTTP listener, TrustedHosts) | Section 5.6.2 |
| `Detect-AuditPolicies.ps1` | M-01 | Detects if advanced audit policies are enabled | Section 5.4.3 |
| `Detect-PowerShellLogging.ps1` | - | Checks PowerShell script block and module logging | Section 5.5.6 |
| `Detect-ADRecycleBin.ps1` | L-01 | Detects if AD Recycle Bin is enabled | Section 5.5.1 |

### Audit Scripts (5 scripts)

Audit scripts enable logging and monitoring modes to assess the impact of proposed changes before enforcement.

| Script | Purpose | Monitoring Period | Events to Monitor |
|--------|---------|-------------------|-------------------|
| `Enable-NTLMAuditing.ps1` | Identify systems using NTLM authentication | 48-72 hours | Security: Event ID 4624 |
| `Enable-LDAPDiagnostics.ps1` | Identify unsigned LDAP connections | 48-72 hours | Directory Service: Event ID 2889 |
| `Enable-ADCSLogging.ps1` | Monitor ADCS certificate enrollment activity | 7 days | Application log |
| `Review-RDPAccess.ps1` | Identify legitimate RDP users and access patterns | Ongoing | Security: Event ID 4624 (LogonType 10) |
| `Review-WinRMUsage.ps1` | Identify WinRM usage and client systems | 7 days | WinRM/Operational log |

### Mitigation Scripts (15 scripts)

Mitigation scripts implement security hardening measures based on findings.

| Script | Remediation | Risk Level | Implementation Phase |
|--------|-------------|------------|---------------------|
| `Set-PasswordPolicy.ps1` | Increase minimum password length to 12+ characters | HIGH | Phase 1 (0-7 days) |
| `Disable-NTLMv1.ps1` | Set LmCompatibilityLevel to 5 (refuse NTLMv1/LM) | HIGH | Phase 1 (0-7 days) |
| `Deploy-WindowsLAPS.ps1` | Deploy Windows LAPS for local admin passwords | HIGH | Phase 2 (7-14 days) |
| `Disable-PrintSpooler.ps1` | Disable Print Spooler on all Domain Controllers | HIGH | Phase 1 (0-7 days) |
| `Block-RPCCoercion.ps1` | Block NTLM outbound traffic from DCs | HIGH | Phase 2 (7-14 days) |
| `Enable-LDAPSigning.ps1` | Require LDAP signing on Domain Controllers | MEDIUM | Phase 3 (14-30 days) |
| `Enable-LDAPChannelBinding.ps1` | Enforce LDAPS channel binding | MEDIUM | Phase 3 (14-30 days) |
| `Secure-ADCSWebEnrollment.ps1` | Remove HTTP binding, enforce HTTPS only | MEDIUM | Phase 3 (14-30 days) |
| `Disable-LLMNR.ps1` | Disable LLMNR via Group Policy | MEDIUM | Phase 4 (30-90 days) |
| `Disable-NetBIOS.ps1` | Disable NetBIOS over TCP/IP | MEDIUM | Phase 4 (30-90 days) |
| `Harden-RDP.ps1` | Enable NLA, high encryption, Restricted Admin mode | MEDIUM | Phase 3 (14-30 days) |
| `Harden-WinRM.ps1` | Remove HTTP listener, enforce HTTPS only | MEDIUM | Phase 3 (14-30 days) |
| `Enable-AdvancedAuditPolicy.ps1` | Apply advanced audit policy baseline | MEDIUM | Phase 3 (14-30 days) |
| `Enable-PowerShellLogging.ps1` | Enable script block and module logging | MEDIUM | Phase 4 (30-90 days) |
| `Enable-ADRecycleBin.ps1` | Enable AD Recycle Bin (irreversible) | LOW | Phase 4 (30-90 days) |

### Verification Scripts (15 scripts)

Verification scripts confirm that security controls have been successfully implemented.

| Script | Validates | Expected Result |
|--------|-----------|-----------------|
| `Verify-PasswordPolicy.ps1` | Password policy changes | MinPasswordLength ≥ 12 |
| `Verify-NTLMv1Disabled.ps1` | NTLMv1 disabled | LmCompatibilityLevel = 5 |
| `Verify-LAPSDeployment.ps1` | LAPS password rotation | Computers have ms-Mcs-AdmPwd attribute |
| `Verify-PrintSpoolerDisabled.ps1` | Print Spooler disabled on DCs | Status=Stopped, StartType=Disabled |
| `Verify-RPCCoercionBlocked.ps1` | NTLM outbound blocked | RestrictSendingNTLMTraffic = 2 |
| `Verify-LDAPSigning.ps1` | LDAP signing required | LDAPServerIntegrity = 2 |
| `Verify-LDAPChannelBinding.ps1` | Channel binding enforced | LdapEnforceChannelBinding = 1 or 2 |
| `Verify-ADCSWebHTTPS.ps1` | HTTPS-only enrollment | No HTTP bindings |
| `Verify-LLMNRDisabled.ps1` | LLMNR disabled | EnableMulticast = 0 |
| `Verify-NetBIOSDisabled.ps1` | NetBIOS disabled | TcpipNetbiosOptions = 2 |
| `Verify-RDPHardened.ps1` | RDP hardening applied | NLA=1, Encryption=3 |
| `Verify-WinRMHardened.ps1` | WinRM secured | HTTPS listener only |
| `Verify-AuditPolicy.ps1` | Audit policy enabled | Critical categories enabled |
| `Verify-PowerShellLogging.ps1` | PowerShell logging active | Script block logging enabled |
| `Verify-ADRecycleBin.ps1` | Recycle Bin enabled | EnabledScopes = forest DN |

### Rollback Scripts (8 scripts)

Rollback scripts restore previous configurations if issues arise during implementation.

| Script | Rollback Action | When to Use |
|--------|----------------|-------------|
| `Rollback-PasswordPolicy.ps1` | Restore previous password settings | User lockout issues |
| `Rollback-NTLMv1.ps1` | Re-enable NTLMv1 (LmCompatibilityLevel=3) | Application authentication failures |
| `Rollback-LAPS.ps1` | Disable LAPS password management | Local admin access issues |
| `Rollback-PrintSpooler.ps1` | Re-enable Print Spooler | Unexpected printing requirements |
| `Rollback-RPCCoercion.ps1` | Allow NTLM outbound | Legitimate DC outbound auth needed |
| `Rollback-LDAPSigning.ps1` | Disable LDAP signing requirement | Application LDAP failures |
| `Rollback-LLMNR.ps1` | Re-enable LLMNR | Name resolution issues |
| `Rollback-NetBIOS.ps1` | Re-enable NetBIOS | Legacy application issues |

## Implementation Workflow

All scripts follow the **Detection-First Methodology**:

```
1. DETECT     → Run detection script to identify vulnerability
2. AUDIT      → Enable audit mode to assess impact (48-72 hours)
3. ASSESS     → Analyze audit logs, identify dependencies
4. MITIGATE   → Implement security control
5. VERIFY     → Confirm successful implementation
6. ROLLBACK   → Restore previous state if issues arise (optional)
```

## Usage Guidelines

### Prerequisites

- **PowerShell 5.1+** or **PowerShell 7+**
- **Active Directory PowerShell Module** (`Import-Module ActiveDirectory`)
- **Administrative privileges** on target systems
- **Domain Admin** or equivalent rights for AD-wide changes

### Running Detection Scripts

```powershell
# Example: Detect weak password policy
.\detection\Detect-WeakPasswordPolicy.ps1

# Example: Detect NTLMv1 on specific DC
.\detection\Detect-NTLMv1Authentication.ps1 -ComputerName "DC01"

# Example: Detect Print Spooler on all DCs
.\detection\Detect-PrintSpoolerOnDCs.ps1
```

### Running Audit Scripts

```powershell
# Example: Enable NTLM auditing for 72 hours
.\audit\Enable-NTLMAuditing.ps1 -AuditDuration 72

# Example: Enable LDAP diagnostics on specific DC
.\audit\Enable-LDAPDiagnostics.ps1 -DomainController "DC01"
```

### Running Mitigation Scripts

```powershell
# Example: Disable NTLMv1 authentication
.\mitigation\Disable-NTLMv1.ps1

# Example: Disable Print Spooler on DCs
.\mitigation\Disable-PrintSpooler.ps1

# Example: Set password policy
.\mitigation\Set-PasswordPolicy.ps1 -MinPasswordLength 14
```

### Running Verification Scripts

```powershell
# Example: Verify NTLMv1 is disabled
.\verification\Verify-NTLMv1Disabled.ps1

# Example: Verify LAPS deployment
.\verification\Verify-LAPSDeployment.ps1
```

### Running Rollback Scripts

```powershell
# Example: Rollback NTLMv1 restrictions
.\rollback\Rollback-NTLMv1.ps1

# Example: Rollback LDAP signing
.\rollback\Rollback-LDAPSigning.ps1
```

## Phased Implementation Timeline

| Phase | Duration | Priority | Focus |
|-------|----------|----------|-------|
| **Phase 1** | 0-7 days | HIGH | Password policy, NTLMv1, Print Spooler |
| **Phase 2** | 7-14 days | HIGH | LAPS, RPC coercion mitigation |
| **Phase 3** | 14-30 days | MEDIUM | LDAP signing/binding, ADCS, RDP/WinRM, audit policies |
| **Phase 4** | 30-90 days | LOW/MEDIUM | LLMNR/NetBIOS, PowerShell logging, AD Recycle Bin |

## Important Notes

### ⚠️ Pre-Implementation Requirements

1. **Always run detection scripts first** to confirm vulnerability exists
2. **Enable audit mode** for 48-72 hours minimum before enforcement
3. **Test in pilot OU** before domain-wide deployment
4. **Document baseline settings** before making changes
5. **Have rollback plan ready** in case of issues
6. **Coordinate with change management** process

### ⚠️ Irreversible Operations

Some operations cannot be reversed:

- **Enable-ADRecycleBin.ps1**: Enabling AD Recycle Bin is permanent
- **Windows LAPS schema changes**: AD schema modifications are permanent

### ⚠️ High-Impact Changes

The following changes may impact business operations:

- **Disable-NTLMv1.ps1**: May break legacy application authentication
- **Enable-LDAPSigning.ps1**: May block applications without signing support
- **Disable-LLMNR.ps1**: May affect name resolution for legacy applications
- **Disable-NetBIOS.ps1**: May break applications using NetBIOS names

**Always audit first!**

## Color Coding in Output

Scripts use color-coded output for clarity:

- 🟢 **Green**: Secure configuration or successful operation
- 🔴 **Red**: Vulnerable configuration or error
- 🟡 **Yellow**: Warning or informational message
- ⚪ **White**: General information
- 🔵 **Cyan**: Section headers

## Compliance and Standards

All scripts align with:

- **ISO/IEC 27001:2022** (Controls 5.17, 5.18, 5.34, 8.2, 8.5, 8.8, 8.15, 8.24)
- **MITRE ATT&CK Framework** (Techniques: T1078.003, T1187, T1201, T1557, T1557.001)
- **NIST Cybersecurity Framework**
- **CIS Critical Security Controls**
- **Microsoft Security Baselines**

## References

- **Project Documentation**: `Project_Plan_and_Structure.md`
- **PingCastle Assessment Report**: See Appendix H in project documentation
- **Microsoft Security Baselines**: https://learn.microsoft.com/en-us/windows/security/
- **MITRE ATT&CK**: https://attack.mitre.org/
- **ISO 27001:2022**: ISO/IEC 27001:2022 Information Security Management

## Support

For issues or questions:

1. Review the project documentation (`Project_Plan_and_Structure.md`)
2. Check script header comments for specific guidance
3. Review audit logs during audit phase
4. Use rollback scripts if issues occur
5. Document all changes in change management system

## Script Status Summary

| Category | Scripts Created | Status |
|----------|----------------|---------|
| Detection | 15 | ✅ Complete |
| Audit | 2 of 5 | 🟡 Sample created |
| Mitigation | 0 of 15 | ⚪ Template available |
| Verification | 0 of 15 | ⚪ Template available |
| Rollback | 0 of 8 | ⚪ Template available |

**Total Scripts Extracted**: 17 scripts created  
**Total Scripts Documented**: 58 scripts catalogued

---

**Project**: Active Directory Hardening - Mitigating Risks from Default Configurations  
**Author**: Ahmed Bayoumy  
**Date**: February 27, 2026  
**Version**: 1.0

---

## Resources

- Windows security auditing overview: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-policy-overview
- Microsoft security baselines and tools: https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines
