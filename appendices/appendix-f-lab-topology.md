[← Back to Main](../README.md)

# Appendix F: Lab Topology Diagrams

## Laboratory Infrastructure Architecture

This appendix describes the complete laboratory environment used for Active Directory security assessment and hardening implementation.

---

## Lab Environment Overview

**Environment Type:** Isolated Active Directory Lab  
**Purpose:** Security assessment, configuration testing, and hardening validation  
**Isolation:** Air-gapped from production networks  
**Assessment Date:** December 7, 2025  

---

## Network Topology

### High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                    LAB NETWORK - 192.168.51.0/24                      │
│                         (Isolated Environment)                         │
└──────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                          Management Workstation                          │
│                          (Windows 11 Enterprise)                         │
│                              CLIENT01                                    │
│                           192.168.51.100                                 │
│                                                                          │
│   Tools: RSAT, PingCastle, PowerShell, Remote Desktop, GPO Management   │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ RDP / WinRM / GPO Management
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│                        ACTIVE DIRECTORY FOREST                           │
│                         Domain: contoso.com                              │
│                    Forest Functional Level: 2016                         │
│                    Domain Functional Level: 2016                         │
└─────────────────────────────────────────────────────────────────────────┘

┌───────────────────────┐         ┌───────────────────────┐
│   Domain Controller 1  │◄───────►│   Domain Controller 2  │
│        DC01           │  Replic.│         DC02          │
│ 192.168.51.10         │         │  192.168.51.12        │
│                       │         │                       │
│ Roles:                │         │ Roles:                │
│ - PDC Emulator        │         │ - (Secondary DC)      │
│ - RID Master          │         │                       │
│ - Infrastructure Mstr │         │                       │
│ - Schema Master       │         │                       │
│ - Domain Naming Mstr  │         │                       │
│                       │         │                       │
│ OS: Windows Server    │         │ OS: Windows Server    │
│     2022 (Nov 2025)   │         │     2022 (Nov 2025)   │
└───────────────────────┘         └───────────────────────┘
            │                                 │
            │                                 │
            └────────────┬────────────────────┘
                         │
                         │ LDAPS / Kerberos / AD Replication
                         ↓
           ┌──────────────────────────────┐
           │   Certificate Authority      │
           │         CA01                 │
           │     192.168.51.20            │
           │                              │
           │ Role: Enterprise Root CA     │
           │ Services:                    │
           │ - Active Directory           │
           │   Certificate Services       │
           │ - Web Enrollment (HTTPS)     │
           │                              │
           │ OS: Windows Server 2022      │
           └──────────────────────────────┘
```

---

## Detailed Component Specifications

### Domain Controller 1 (DC01)

**Hostname:** DC01  
**FQDN:** DC01.contoso.com  
**IP Address:** 192.168.51.10  
**Subnet Mask:** 255.255.255.0  
**Default Gateway:** 192.168.51.1  
**DNS Servers:** 127.0.0.1 (self), 192.168.51.12 (DC02)  

**Operating System:**  
- Windows Server 2022 Standard (Desktop Experience)
- Build: November 2025 (latest cumulative update)
- Edition ID: ServerStandard

**Roles and Features:**
- Active Directory Domain Services (AD DS)
- DNS Server
- File and Storage Services

**FSMO Roles Held:**
1. PDC Emulator
2. RID Master
3. Infrastructure Master
4. Schema Master
5. Domain Naming Master

**Configuration:**
- Forest Root Domain Controller
- Global Catalog: Yes
- Read-Only: No
- Replication Partners: DC02

**Installed Tools:**
- Remote Server Administration Tools (RSAT)
- Active Directory Administrative Center
- Group Policy Management Console
- DNS Manager

---

### Domain Controller 2 (DC02)

**Hostname:** DC02  
**FQDN:** DC02.contoso.com  
**IP Address:** 192.168.51.12  
**Subnet Mask:** 255.255.255.0  
**Default Gateway:** 192.168.51.1  
**DNS Servers:** 192.168.51.10 (DC01), 127.0.0.1 (self)  

**Operating System:**  
- Windows Server 2022 Standard (Desktop Experience)
- Build: November 2025 (latest cumulative update)
- Edition ID: ServerStandard

**Roles and Features:**
- Active Directory Domain Services (AD DS)
- DNS Server
- File and Storage Services

**FSMO Roles Held:**
- None (all roles on DC01)

**Configuration:**
- Additional Domain Controller (replica)
- Global Catalog: Yes
- Read-Only: No
- Replication Partners: DC01

---

### Certificate Authority (CA01)

**Hostname:** CA01  
**FQDN:** CA01.contoso.com  
**IP Address:** 192.168.51.20  
**Subnet Mask:** 255.255.255.0  
**Default Gateway:** 192.168.51.1  
**DNS Servers:** 192.168.51.10, 192.168.51.12  

**Operating System:**  
- Windows Server 2022 Standard (Desktop Experience)
- Build: November 2025 (latest cumulative update)

**Roles and Features:**
- Active Directory Certificate Services (AD CS)
  - Certification Authority
  - Certificate Enrollment Web Service
  - Certificate Enrollment Policy Web Service
- Internet Information Services (IIS)
- Web Server (IIS) Support

**CA Configuration:**
- CA Type: Enterprise Root CA
- CA Name: contoso-CA01-CA
- Key Length: 4096-bit RSA
- Cryptographic Provider: RSA#Microsoft Software Key Storage Provider
- Hash Algorithm: SHA256
- Validity Period: 10 years
- CRL Publication Interval: 1 week
- Delta CRL Publication Interval: 1 day

**Certificate Templates Issued:**
- Web Server
- Computer
- Domain Controller
- Domain Controller Authentication
- User
- Administrator

**Web Enrollment:**
- HTTP URL: http://ca01.contoso.com/certsrv (DISABLED - security finding)
- HTTPS URL: https://ca01.contoso.com/certsrv (ENABLED after remediation)
- IIS Bindings: HTTPS only (port 443)

---

### Management Workstation (CLIENT01)

**Hostname:** CLIENT01  
**FQDN:** CLIENT01.contoso.com  
**IP Address:** 192.168.51.100  
**Subnet Mask:** 255.255.255.0  
**Default Gateway:** 192.168.51.1  
**DNS Servers:** 192.168.51.10, 192.168.51.12  

**Operating System:**  
- Windows 11 Enterprise (23H2)
- Latest cumulative updates installed

**Domain Membership:**
- Domain: contoso.com
- Organizational Unit: OU=Workstations,DC=contoso,DC=com

**Installed Software:**
- Remote Server Administration Tools (RSAT) for Windows 11
  - Active Directory Users and Computers
  - Group Policy Management
  - DNS Management Tools
  - Active Directory Certificate Services Tools
- PowerShell 7.x
- Windows Terminal
- Netwrix PingCastle Basic Edition 3.4.1.38
- Visual Studio Code
- Microsoft Edge (Chromium-based)

**User Accounts Used:**
- Local Administrator (LAPS-managed after implementation)
- Domain Admin account for administrative tasks
- Standard domain user for testing

---

## Active Directory Structure

### Organizational Unit (OU) Design

```
contoso.com (Domain Root)
│
├── Domain Controllers (Built-in)
│   ├── DC01
│   └── DC02
│
├── Servers
│   └── CA01
│
├── Workstations
│   └── CLIENT01
│
├── Users
│   ├── Administrators
│   ├── Standard Users
│   └── Service Accounts
│
└── Groups
    ├── Security Groups
    │   ├── gMSA-Authorized-Servers
    │   └── LAPS-Administrators
    └── Distribution Groups
```

---

## Network Services

### DNS Configuration

**Primary DNS Server:** DC01 (192.168.51.10)  
**Secondary DNS Server:** DC02 (192.168.51.12)  

**DNS Zones:**
- Forward Lookup Zone: contoso.com (Active Directory-Integrated)
- Reverse Lookup Zone: 51.168.192.in-addr.arpa (Active Directory-Integrated)

**DNS Records (Sample):**
```
A Records:
  dc01.contoso.com        → 192.168.51.10
  dc02.contoso.com        → 192.168.51.12
  ca01.contoso.com        → 192.168.51.20
  client01.contoso.com    → 192.168.51.100

SRV Records (Auto-created by AD):
  _ldap._tcp.contoso.com
  _kerberos._tcp.contoso.com
  _kpasswd._tcp.contoso.com
  _gc._tcp.contoso.com

PTR Records:
  10.51.168.192.in-addr.arpa  → dc01.contoso.com
  12.51.168.192.in-addr.arpa  → dc02.contoso.com
  20.51.168.192.in-addr.arpa  → ca01.contoso.com
  100.51.168.192.in-addr.arpa → client01.contoso.com
```

---

### Active Directory Sites and Services

**Default Site Configuration (Pre-Remediation):**
- Site: Default-First-Site-Name
- Subnets: None configured (Finding M-05)
- Site Links: DEFAULTIPSITELINK

**Remediated Configuration:**
- Site: Default-First-Site-Name
- Subnets: 192.168.51.0/24
- Site Links: DEFAULTIPSITELINK
  - Cost: 100
  - Replication Interval: 180 minutes

---

## Security Baseline State

### Pre-Hardening Configuration (Initial State)

**Password Policy:**
- Minimum Password Length: 7 characters
- Password Complexity: Enabled
- Password History: 24 passwords
- Maximum Password Age: 42 days
- Account Lockout Threshold: Not configured

**Authentication:**
- LM Authentication Level: Not explicitly configured (default = 3)
- NTLM Auditing: Disabled
- Kerberos Encryption Types: AES256, AES128, RC4

**Services (Domain Controllers):**
- Print Spooler: Running (HIGH RISK)
- Remote Desktop: Enabled (with default settings)
- WinRM: Enabled (HTTP listener active)

**LDAP Security:**
- LDAP Signing: Not required
- LDAPS Channel Binding: Not configured
- LDAPS Port 636: Available but not enforced

**Logging:**
- Basic Audit Policy: Enabled
- Advanced Audit Policy: Not configured
- PowerShell Logging: Disabled

**LAPS:**
- Deployment Status: Not deployed

---

## Network Diagram - Before and After Hardening

### BEFORE Hardening (Vulnerable Configuration)

```
Attack Surface Visualization:

┌─────────────────────────────────────────────────────────────────┐
│                      BEFORE HARDENING                            │
│                   (High Attack Surface)                          │
└─────────────────────────────────────────────────────────────────┘

Domain Controllers (DC01, DC02):
├── Print Spooler RUNNING ⚠️ (CVE-2021-34527 PrintNightmare)
├── RPC Coercion Interfaces EXPOSED ⚠️ (CVE-2021-36942 PetitPotam)
├── NTLMv1 ALLOWED ⚠️ (Relay attacks, hash cracking)
├── LDAP Signing NOT REQUIRED ⚠️ (MITM attacks)
├── LDAPS Channel Binding DISABLED ⚠️
├── RDP with weak encryption ⚠️
└── WinRM HTTP listener (port 5985) ⚠️

Certificate Authority (CA01):
├── Web Enrollment via HTTP ⚠️ (Port 80 - cleartext)
└── HTTPS available but not enforced

Workstation (CLIENT01):
├── Local Admin password STATIC ⚠️ (no LAPS)
├── LLMNR ENABLED ⚠️ (MITM risk)
├── NetBIOS ENABLED ⚠️ (legacy protocol)
└── PowerShell logging DISABLED ⚠️

Network Protocols:
├── NTLMv1/LM authentication allowed
├── LDAP unsigned binds accepted
├── RPC unauthenticated calls possible
└── Legacy name resolution protocols active
```

---

### AFTER Hardening (Reduced Attack Surface)

```
┌─────────────────────────────────────────────────────────────────┐
│                      AFTER HARDENING                             │
│                 (Minimized Attack Surface)                       │
└─────────────────────────────────────────────────────────────────┘

Domain Controllers (DC01, DC02):
├── Print Spooler DISABLED ✓ (Service stopped and disabled)
├── NTLM Outbound BLOCKED ✓ (RestrictSendingNTLMTraffic = 2)
├── NTLMv2 ONLY enforced ✓ (LmCompatibilityLevel = 5)
├── LDAP Signing REQUIRED ✓ (LDAPServerIntegrity = 2)
├── LDAPS Channel Binding ENABLED ✓ (LdapEnforceChannelBinding = 1)
├── RDP with NLA + High Encryption ✓
├── WinRM HTTPS only (HTTP listener removed) ✓
└── Advanced Audit Policy ACTIVE ✓

Certificate Authority (CA01):
├── Web Enrollment HTTP DISABLED ✓ (Port 80 binding removed)
└── HTTPS ONLY enforced ✓ (Port 443)

Workstation (CLIENT01):
├── LAPS deployed ✓ (14-char password, 30-day rotation)
├── LLMNR DISABLED ✓ (EnableMulticast = 0)
├── NetBIOS DISABLED ✓ (TcpipNetbiosOptions = 2)
└── PowerShell Script Block Logging ENABLED ✓

Network Protocols:
├── NTLMv2 only (LM & NTLMv1 refused)
├── LDAP signing enforced
├── LDAPS with channel binding
└── Modern protocols only (LLMNR/NetBIOS disabled)

Password Policy:
├── Minimum length: 12 characters ✓
├── Complexity: Enabled ✓
├── Password history: 24 passwords ✓
└── Account lockout: 5 attempts ✓
```

---

## Replication Topology

### AD Replication Visualization

```
┌──────────────────────────────────────────────────────────────┐
│          Active Directory Replication Topology                │
└──────────────────────────────────────────────────────────────┘

Site: Default-First-Site-Name
Subnet: 192.168.51.0/24

┌─────────────────────┐
│       DC01          │
│  (All FSMO Roles)   │
│  192.168.51.10      │
└─────────────────────┘
          │
          │ Bidirectional Replication
          │ Protocol: RPC over IP
          │ Schedule: Every 15 minutes
          │
          ↓
┌─────────────────────┐
│       DC02          │
│ (Replica DC + GC)   │
│  192.168.51.12      │
└─────────────────────┘

Replication Partnerships:
├── DC01 → DC02 (Inbound/Outbound)
├── DC02 → DC01 (Inbound/Outbound)
└── Replication Interval: 180 minutes (default)

Global Catalog Servers:
├── DC01 (Port 3268 TCP, 3269 TCP/SSL)
└── DC02 (Port 3268 TCP, 3269 TCP/SSL)
```

---

## Firewall Configuration

### Domain Controller Firewall Rules (Post-Hardening)

**Inbound Rules (Allowed):**
```
Service: Active Directory Domain Services
Ports: TCP 389 (LDAP), TCP 636 (LDAPS), TCP 3268 (GC), TCP 3269 (GC-SSL)
Scope: Domain network only

Service: Kerberos
Ports: TCP 88, UDP 88
Scope: Domain network only

Service: DNS
Ports: TCP 53, UDP 53
Scope: Domain network only

Service: RPC
Ports: TCP 135, Dynamic RPC (49152-65535)
Scope: Domain network only

Service: SMB
Ports: TCP 445
Scope: Domain network only

Service: Remote Desktop (RDP)
Ports: TCP 3389
Scope: Restricted to management IPs (192.168.51.100) or DISABLED

Service: WinRM (HTTPS)
Ports: TCP 5986
Scope: Restricted to management IPs (192.168.51.100)
```

**Inbound Rules (Blocked):**
```
Service: WinRM HTTP
Ports: TCP 5985
Status: BLOCKED (listener removed)

Service: Print Spooler
Ports: (Service disabled)
Status: N/A
```

---

## Lab Access and Management

### Administrative Access Methods

**Primary Management Methods:**
1. **Remote Desktop (RDP)** to CLIENT01
   - From CLIENT01, RDP to servers with Restricted Admin mode
   
2. **PowerShell Remoting (WinRM over HTTPS)**
   ```powershell
   # From CLIENT01
   $session = New-PSSession -ComputerName DC01.contoso.com -UseSSL
   Enter-PSSession -Session $session
   ```

3. **Group Policy Management Console (GPMC)**
   - Managed from CLIENT01 using RSAT tools

4. **Active Directory Administrative Center**
   - Managed from CLIENT01 using RSAT tools

---

### Backup and Recovery

**Backup Schedule:**
- System State backups of DC01 and DC02: Daily
- GPO backups: After each change
- Certificate Authority backups: Weekly
- Full bare-metal recovery image: Monthly

**Snapshot Schedule (Virtualization):**
- Pre-change snapshots: Before each hardening phase
- Retention: 7 days
- Snapshot naming: `[DATE]_[DESCRIPTION]_PRE-CHANGE`

---

## Assessment Tools Deployed

### Security Assessment Tools

**Netwrix PingCastle Basic Edition 3.4.1.38**
- Location: C:\Tools\PingCastle on CLIENT01
- Execution: Run as Domain Admin
- Output: HTML report + XML data
- Assessment Date: December 7, 2025

**Microsoft Security Compliance Toolkit (SCT)**
- Location: C:\Tools\SCT on CLIENT01
- Purpose: GPO baseline comparison
- Policy Analyzer included

**PowerShell Scripts**
- Custom detection, audit, and verification scripts
- Location: C:\Scripts\ on CLIENT01 and DCs
- Version control: Git repository

---

## Lab Limitations and Scope

**Limitations:**
- Single Active Directory site (no multi-site replication testing)
- No Azure AD / Hybrid configuration
- No external trust relationships
- Limited to Windows Server 2022 / Windows 11 (no legacy OS versions)
- No third-party applications requiring legacy protocols

**Out of Scope:**
- Penetration testing / exploitation attempts
- Physical security controls
- Backup/disaster recovery testing
- Performance/scalability testing
- Multi-forest scenarios

---

[← Back to Main](../README.md)

---

## Resources

- Active Directory logical structure and topology: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/active-directory-logical-structure
