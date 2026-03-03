# Chapter 7: Additional Hardening Actions

[← Previous: Configuration Hardening and Security Enhancements](06-configuration-hardening.md) | [Next: Results and Analysis →](08-results-analysis.md)

---

## Chapter Overview

This chapter outlines supplementary security hardening actions that extend beyond the baseline remediations covered in the previous chapters. These actions focus on robust remote management and the implementation of highly secure service accounts to further reduce the Active Directory attack surface.

## 7.1 Hardening Remote Access (RDP & WinRM)

Securing remote administrative access is a critical step in defending Active Directory against lateral movement, credential theft, and unauthorized control. Proper configuration ensures that only authorized administrators can remotely manage critical systems over encrypted and authenticated channels.

For the comprehensive, step-by-step guide on securing these protocols—including Group Policy implementations, certificate-based authentication, and firewall restrictions—refer to the dedicated guide:

*   [**RDP and WinRM Hardening Guide**](../additional-hardening/rdp-winrm-guide.md)

## 7.2 Implementing Group Managed Service Accounts (gMSA)

Service accounts are frequently targeted by attackers because they often hold elevated privileges and are typically configured with passwords that never expire. Transitioning from legacy service accounts to Group Managed Service Accounts (gMSAs) eliminates the need for manual password management and prevents credential theft via techniques like Kerberoasting.

For detailed deployment instructions, Active Directory prerequisites, and operational procedures for migrating to gMSAs, refer to the dedicated guide:

*   [**gMSA Deployment Guide**](../additional-hardening/gmsa-guide.md)

---

[← Previous: Configuration Hardening and Security Enhancements](06-configuration-hardening.md) | [Next: Results and Analysis →](08-results-analysis.md)

---

## Resources

- Remote Desktop Services Security: https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-security
- Windows Remote Management Security: https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management
- Group Managed Service Accounts overview: https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview
