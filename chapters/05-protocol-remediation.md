# Chapter 5: Mitigating Insecure Protocols and Authentication

[← Previous: Security Configuration Assessment and Risk Analysis](04-risk-assessment.md) | [Next: Configuration Hardening and Security Enhancements →](06-configuration-hardening.md)

---

## Chapter Overview

This chapter addresses vulnerabilities related to insecure authentication protocols and legacy communication methods identified in the PingCastle assessment. All remediations follow a standardized workflow to ensure business continuity:

**Standardized Workflow:**
1. **Detection:** PowerShell command to confirm the issue exists
2. **Audit Mode:** Enable logging/monitoring to identify business impact
3. **Impact Assessment:** What to monitor during audit period (48-72 hours)
4. **Mitigation:** Step-by-step implementation instructions  
5. **Verification:** PowerShell command to confirm successful implementation
6. **Rollback:** Procedure if issues arise

**Protocols Addressed in This Chapter:**
- NTLM (NTLMv1/LM ban) - Covered in Chapter 4, H-02
- RPC Coercion (NTLM outbound restrictions) - Covered in Chapter 4, H-05
- LDAP Signing and Channel Binding
- ADCS Web Enrollment (HTTP to HTTPS)
- LLMNR (Link-Local Multicast Name Resolution)
- NetBIOS over TCP/IP
- Remote Desktop Protocol (RDP) hardening
- Windows Remote Management (WinRM) hardening

---

## 5.1 Protocol Remediation Strategy Overview

### Phased Approach

Protocol remediations are implemented in four phases based on risk severity and business impact:

| Phase | Timeline | Focus | Protocols |
|-------|----------|-------|-----------|
| **Phase 1** | 0-7 days | Critical vulnerabilities | NTLM restrictions, RPC coercion |
| **Phase 2** | 7-14 days | High-priority hardening | LAPS, Print Spooler |
| **Phase 3** | 14-30 days | Protocol security | LDAP signing, LDAPS binding, ADCS HTTPS |
| **Phase 4** | 30-90 days | Additional security | LLMNR, NetBIOS, RDP/WinRM |

### Testing Approach

**Always Enable Audit Mode First:**
- Every protocol change begins with audit/logging mode
- Collect usage data for minimum 48-72 hours (7 days for major changes)
- Identify affected systems and applications
- Contact stakeholders before enforcement

**Pilot OU Testing:**
- Test changes in LAPS-Pilot OU first
- Monitor for 7 days minimum
- Expand to additional test systems
- Deploy domain-wide only after successful pilot

### Change Management Integration

**Required for Each Remediation:**
- Change management ticket with business justification
- Stakeholder identification and approval
- Impact assessment documentation
- Implementation window scheduling
- Rollback plan testing
- Post-implementation verification

---

## 5.2 Phase 1: Critical Protocol Mitigations (0-7 Days)

### 5.2.1 Ban NTLMv1/LM Authentication

**Finding Reference:** HIGH risk finding H-02 (detailed in Chapter 4)

This remediation was fully detailed in Chapter 4, Section 4.4 (H-02). Summary:

**Quick Reference:**

```powershell
# Detection
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel"

# Audit First (48-72 hours)
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
    -Name "AuditReceivingNTLMTraffic" -Value 2 -PropertyType DWord -Force

# Mitigation
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LmCompatibilityLevel" -Value 5 -Type DWord

# Verification
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel"
# Expected: 5
```

Refer to Chapter 4, Section 4.4, Finding H-02 for complete implementation details.

---

### 5.2.2 Mitigate RPC Coercion Attacks (Restrict NTLM Outbound)

**Finding Reference:** HIGH risk finding H-05 (detailed in Chapter 4)

This remediation was fully detailed in Chapter 4, Section 4.4 (H-05). Summary:

**Quick Reference:**

```powershell
# Detection
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RestrictSendingNTLMTraffic"

# Audit First (48-72 hours)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
    -Name "RestrictSendingNTLMTraffic" -Value 1 -Type DWord

# Mitigation
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
    -Name "RestrictSendingNTLMTraffic" -Value 2 -Type DWord

# Verification
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
    -Name "RestrictSendingNTLMTraffic"
# Expected: 2
```

Refer to Chapter 4, Section 4.4, Finding H-05 for complete implementation details.

---

## 5.3 Phase 3: LDAP Protocol Security (14-30 Days)

### 5.3.1 LDAP Signing Requirement

**Finding Reference:** MEDIUM risk finding M-03

**Risk:** Unsigned LDAP traffic can be intercepted and modified (man-in-the-middle attacks).

**Detection:**

```powershell
# Check current LDAP signing requirement
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue

# Value meanings:
# 0 or not present = No signing required (VULNERABLE)
# 1 = Signing negotiated (accept unsigned if client doesn't support)
# 2 = Signing required (reject unsigned binds) - SECURE
```

**Audit First:**

```powershell
# Enable LDAP diagnostics to identify clients using unsigned LDAP
reg add "HKLM\System\CurrentControlSet\Services\NTDS\Diagnostics" `
    /v "16 LDAP Interface Events" /t REG_DWORD /d 2 /f

# Monitor Event 2889 for unsigned LDAP binds (48-72 hours)
Get-WinEvent -FilterHashtable @{LogName='Directory Service';ID=2889} -MaxEvents 100 | 
    Format-Table TimeCreated, Message -Wrap

# Event 2889 indicates:
# - Client IP address using unsigned LDAP
# - User account performing unsigned bind
# - Number of unsigned binds in last 24 hours
```

**Impact Assessment:**

Monitor audit logs for 48-72 hours:
- Identify LDAP clients not supporting signing
- Common culprits: Legacy applications, network devices, printers, older Linux systems
- Contact application owners to enable LDAP signing in client configuration
- Plan exceptions or application updates

**Mitigation:**

```powershell
# Require LDAP signing on all Domain Controllers
$DCs = @("DC01", "DC02")
foreach ($dc in $DCs) {
    Invoke-Command -ComputerName $dc -ScriptBlock {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
            -Name "LDAPServerIntegrity" -Value 2
        # Value 2 = Require signing
    }
}

# Or via Group Policy (Domain Controllers OU):
# Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options
# "Domain controller: LDAP server signing requirements" = "Require signing"

# Restart not required, but Group Policy update needed
gpupdate /force
```

**Verification:**

```powershell
foreach ($dc in $DCs) {
    Invoke-Command -ComputerName $dc -ScriptBlock {
        Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
            -Name "LDAPServerIntegrity"
    }
}
# Expected: LDAPServerIntegrity = 2

# Monitor for rejected unsigned binds
Get-WinEvent -FilterHashtable @{LogName='Directory Service';ID=2887,2888} -MaxEvents 50
# Event 2887: Client attempted unsigned bind and was rejected
```

**Rollback:**

```powershell
foreach ($dc in $DCs) {
    Invoke-Command -ComputerName $dc -ScriptBlock {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
            -Name "LDAPServerIntegrity" -Value 1
        # Value 1 = Negotiate (accept unsigned)
    }
}
```

---

### 5.3.2 LDAPS Channel Binding

**Finding Reference:** MEDIUM risk finding M-02

**Risk:** Without channel binding, LDAPS connections vulnerable to relay attacks even over encrypted channels.

**Detection:**

```powershell
# Check LDAPS channel binding configuration
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue

# Value meanings:
# 0 or not present = Never require channel binding (VULNERABLE)
# 1 = When supported (negotiate)
# 2 = Always require channel binding - MOST SECURE
```

**Audit First:**

```powershell
# Enable LDAP diagnostics (if not already from LDAP signing audit)
reg add "HKLM\System\CurrentControlSet\Services\NTDS\Diagnostics" `
    /v "16 LDAP Interface Events" /t REG_DWORD /d 2 /f

# Monitor Events 3039, 3040 for channel binding issues
Get-WinEvent -FilterHashtable @{LogName='Directory Service';ID=3039,3040} `
    -MaxEvents 100 -ErrorAction SilentlyContinue | 
    Format-Table TimeCreated, Message -Wrap

# Event 3039: LDAPS connection without channel binding
# Event 3040: LDAPS connection rejected due to missing channel binding
```

**Impact Assessment:**

- Monitor LDAPS client compatibility for 48-72 hours
- Modern Windows clients (Windows 7+, Server 2008 R2+) support channel binding
- Third-party LDAP clients may need updates
- Test critical applications using LDAPS

**Mitigation:**

```powershell
# Enable LDAPS channel binding (start with value 1 for compatibility)
foreach ($dc in $DCs) {
    Invoke-Command -ComputerName $dc -ScriptBlock {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" `
            -Name "LdapEnforceChannelBinding" -Value 1
        # Value 1 = When supported (negotiate)
        # After testing, can increase to 2 (always require)
    }
}

# Restart not required
gpupdate /force
```

**Verification:**

```powershell
foreach ($dc in $DCs) {
    Invoke-Command -ComputerName $dc -ScriptBlock {
        Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" `
            -Name "LdapEnforceChannelBinding"
    }
}
# Expected: LdapEnforceChannelBinding = 1 (or 2 after full testing)

# Monitor for issues
Get-WinEvent -FilterHashtable @{LogName='Directory Service';ID=3039,3040} -MaxEvents 20
```

**Rollback:**

```powershell
foreach ($dc in $DCs) {
    Invoke-Command -ComputerName $dc -ScriptBlock {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" `
            -Name "LdapEnforceChannelBinding" -Value 0
    }
}
```

**Phased Enforcement:**

1. **Week 1-2:** Deploy with value 1 (negotiate), monitor Event 3039
2. **Week 3:** If no issues, increase to value 2 (always require)
3. **Ongoing:** Monitor Event 3040 for rejected connections

---

### 5.3.3 Secure ADCS Web Enrollment (HTTP to HTTPS)

**Finding Reference:** MEDIUM risk finding M-04

**Risk:** Certificate enrollment over HTTP exposes credentials and certificate requests.

**Detection:**

```powershell
# Check IIS bindings on Certificate Authority server
Invoke-Command -ComputerName CA01 -ScriptBlock {
    Import-Module WebAdministration
    Get-WebBinding -Name "Default Web Site" | 
        Select-Object protocol, bindingInformation
}

# Look for HTTP bindings (port 80) on certsrv virtual directory
```

**Audit First:**

```powershell
# Review IIS logs to identify HTTP certificate enrollment usage
Invoke-Command -ComputerName CA01 -ScriptBlock {
    # Check last 7 days of IIS logs for HTTP certsrv access
    $logPath = "C:\inetpub\logs\LogFiles\W3SVC1"
    $logs = Get-ChildItem -Path $logPath -Filter "*.log" | 
        Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)}
    
    foreach ($log in $logs) {
        Get-Content $log.FullName | Select-String "certsrv" | 
            Where-Object {$_ -like "*:80*"} | Select-Object -First 20
    }
}

# Identify users accessing HTTP enrollment (vs HTTPS)
# Notify users to update bookmarks to HTTPS URL
```

**Impact Assessment:**

- Users must update enrollment URLs from HTTP to HTTPS
- Notify users 48 hours in advance
- Provide HTTPS URL: https://ca01.contoso.com/certsrv
- Verify CA has valid certificate for HTTPS

**Mitigation:**

```powershell
# Remove HTTP binding, keep HTTPS only
Invoke-Command -ComputerName CA01 -ScriptBlock {
    Import-Module WebAdministration
    
    # Remove HTTP binding (port 80)
    Remove-WebBinding -Name "Default Web Site" -Protocol "http" -Port 80
    
    # Verify HTTPS binding exists (port 443)
    $httpsBinding = Get-WebBinding -Name "Default Web Site" -Protocol "https"
    if (-not $httpsBinding) {
        Write-Warning "HTTPS binding not found! Add HTTPS binding before removing HTTP."
    }
    
    # Restart IIS to apply changes
    iisreset
}
```

**Verification:**

```powershell
# Verify only HTTPS binding exists
Invoke-Command -ComputerName CA01 -ScriptBlock {
    Import-Module WebAdministration
    Get-WebBinding -Name "Default Web Site" | 
        Select-Object protocol, bindingInformation
}
# Expected: Only HTTPS (port 443) binding, no HTTP (port 80)

# Test web enrollment via HTTPS
Start-Process "https://ca01.contoso.com/certsrv"
```

**Rollback:**

```powershell
# Re-add HTTP binding if needed
Invoke-Command -ComputerName CA01 -ScriptBlock {
    Import-Module WebAdministration
    New-WebBinding -Name "Default Web Site" -Protocol "http" -Port 80
    iisreset
}
```

---

## 5.4 Phase 4: Name Resolution Protocol Security (30-90 Days)

### 5.4.1 Disable LLMNR (Link-Local Multicast Name Resolution)

**Risk:** LLMNR can be poisoned to capture user credentials (LLMNR/NBT-NS poisoning attacks).

**Background:**

LLMNR is a fallback name resolution protocol when DNS fails. Attackers can respond to LLMNR queries and capture authentication attempts.

**Detection:**

```powershell
# Check LLMNR status (via Group Policy or registry)
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -ErrorAction SilentlyContinue

# If not present or value = 1, LLMNR is enabled (VULNERABLE)
# Value 0 = LLMNR disabled (SECURE)
```

**Audit First:**

```powershell
# Deploy to pilot OU for 7 days
# Monitor for name resolution failures
# Check application dependencies

# Monitor DNS and name resolution events
Get-WinEvent -FilterHashtable @{LogName='System';ID=1014,1015} -MaxEvents 100
# Event 1014: Name resolution failed
# Event 1015: Name resolution successful via fallback

# Check for applications using LLMNR
# Most modern environments should rely solely on DNS
```

**Impact Assessment:**

- Test in LAPS-Pilot OU for 7 days
- Monitor helpdesk tickets for name resolution issues
- Legacy applications may rely on LLMNR (rare)
- Most environments should have no issues

**Mitigation:**

```powershell
# Disable LLMNR via Group Policy (preferred)
# Computer Configuration → Administrative Templates → Network → DNS Client
# "Turn off multicast name resolution" = Enabled

# Or via registry (apply to all computers via GPO startup script):
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -Value 0 -Type DWord

# No restart required, but policy refresh needed
gpupdate /force
```

**Verification:**

```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast"
# Expected: EnableMulticast = 0 (disabled)

# Test that DNS is still working
Resolve-DnsName dc01.contoso.com
```

**Rollback:**

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -Value 1
```

---

### 5.4.2 Disable NetBIOS over TCP/IP

**Risk:** NetBIOS-NS vulnerable to poisoning attacks similar to LLMNR.

**Background:**

NetBIOS over TCP/IP (NetBT) is a legacy name resolution and session protocol. Like LLMNR, it can be poisoned to capture credentials.

**Detection:**

```powershell
# Check NetBIOS status on network adapters
Get-WmiObject Win32_NetworkAdapterConfiguration | 
    Where-Object {$_.TcpipNetbiosOptions -ne $null} | 
    Select-Object Description, IPAddress, TcpipNetbiosOptions

# TcpipNetbiosOptions values:
# 0 = Default (use DHCP setting, often enabled) - VULNERABLE
# 1 = Enabled - VULNERABLE
# 2 = Disabled - SECURE
```

**Audit First:**

```powershell
# Test in pilot OU for 7 days
# Monitor for legacy application dependencies
# Check for applications using NetBIOS name resolution

# Very few modern applications require NetBIOS
# Older applications may use NetBIOS sessions (SMB over NetBIOS)
```

**Impact Assessment:**

- Identify legacy applications using NetBIOS names
- Test file sharing (modern SMB uses direct hosting, not NetBIOS)
- Monitor for connectivity issues during pilot
- Most modern environments have no dependencies

**Mitigation:**

```powershell
# Disable NetBIOS over TCP/IP on all network adapters
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True"
foreach ($adapter in $adapters) {
    $result = $adapter.SetTcpipNetbios(2)  # 2 = Disable
    if ($result.ReturnValue -eq 0) {
        Write-Host "Disabled NetBIOS on: $($adapter.Description)"
    } else {
        Write-Warning "Failed to disable NetBIOS on: $($adapter.Description)"
    }
}

# Via Group Policy (preferred method):
# Create startup script with above PowerShell code
# Computer Configuration → Policies → Windows Settings → Scripts → Startup

# Or via DHCP scope option 001 (disable NetBT via DHCP)
```

**Verification:**

```powershell
Get-WmiObject Win32_NetworkAdapterConfiguration | 
    Where-Object {$_.IPEnabled -eq $true} | 
    Select-Object Description, TcpipNetbiosOptions
# All adapters should show: TcpipNetbiosOptions = 2 (Disabled)

# Test file sharing still works (modern SMB)
Test-NetConnection -ComputerName DC01 -Port 445
```

**Rollback:**

```powershell
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True"
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(0)  # 0 = Default (usually enables NetBIOS)
}
```

---

## 5.5 Secure Remote Access Protocols (RDP and WinRM)

### 5.5.1 Remote Desktop Protocol (RDP) Hardening

**Risk:** Insecure RDP configuration exposes remote access to attacks.

**Hardening Objectives:**
- Enable Network Level Authentication (NLA)
- Set encryption to High level
- Enable Restricted Admin Mode
- Implement firewall IP restrictions

**Detection:**

```powershell
# Check if RDP is enabled
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
    -Name "fDenyTSConnections"
# 0 = RDP Enabled, 1 = RDP Disabled

# Check NLA requirement
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "UserAuthentication"
# 0 = NLA Disabled (VULNERABLE), 1 = NLA Enabled (SECURE)

# Check RDP encryption level
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "MinEncryptionLevel"
# 1 = Low, 2 = Client Compatible, 3 = High (SECURE), 4 = FIPS Compliant
```

**Audit First:**

```powershell
# Identify servers with RDP enabled and current usage
# Review RDP access logs (Event ID 4624, LogonType 10)
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 1000 | 
    Where-Object {$_.Properties[8].Value -eq 10} | 
    Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}}, `
        @{N='SourceIP';E={$_.Properties[18].Value}}

# Identify legitimate RDP users and source IPs
# Plan firewall restrictions
```

**Impact Assessment:**

- Identify legitimate RDP users and source networks
- Plan firewall restrictions per server role
- Communication with administrators about NLA requirement
- NLA requires pre-authentication (users need valid credentials to connect)

**Mitigation:**

```powershell
# Enable Network Level Authentication (NLA)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "UserAuthentication" -Value 1

# Set encryption to High
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "MinEncryptionLevel" -Value 3

# Enable Restricted Admin Mode (prevents credential exposure)
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" `
    -Name "DisableRestrictedAdmin" -Value 0 -PropertyType DWord -Force

# Configure firewall to restrict RDP to specific IPs
# Example: Allow RDP only from admin network 192.168.1.0/24
Set-NetFirewallRule -DisplayName "Remote Desktop*" -RemoteAddress "192.168.1.0/24"

# Or create new restrictive rule:
New-NetFirewallRule -DisplayName "RDP - Admin Network Only" `
    -Direction Inbound -Protocol TCP -LocalPort 3389 `
    -RemoteAddress "192.168.1.0/24" -Action Allow -Enabled True

# Disable default RDP rules (too permissive)
Disable-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)"
Disable-NetFirewallRule -DisplayName "Remote Desktop - User Mode (UDP-In)"
```

**Verification:**

```powershell
# Verify NLA enabled
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "UserAuthentication"
# Expected: 1 (NLA enabled)

# Verify High encryption
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "MinEncryptionLevel"
# Expected: 3 (High)

# Verify Restricted Admin Mode
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" `
    -Name "DisableRestrictedAdmin"
# Expected: 0 (Restricted Admin enabled)

# Test RDP connection with Restricted Admin
mstsc /restrictedadmin /v:dc01.contoso.com
```

**Rollback:**

```powershell
# Disable NLA (not recommended)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "UserAuthentication" -Value 0

# Revert encryption level
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "MinEncryptionLevel" -Value 2

# Remove firewall restrictions
Set-NetFirewallRule -DisplayName "Remote Desktop*" -RemoteAddress Any
```

**Additional RDP Security Measures:**

```powershell
# Disable RDP on Domain Controllers (use WinRM/PowerShell Remoting instead)
# Only enable when needed for maintenance

# Change default RDP port (security through obscurity, not primary defense)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "PortNumber" -Value 13389

# Require smart card authentication for RDP (highest security)
# Configure via GPO: Require use of smart cards for interactive logon
```

---

### 5.5.2 Windows Remote Management (WinRM) Hardening

**Risk:** Insecure WinRM configuration exposes PowerShell remoting to attacks.

**Hardening Objectives:**
- Remove HTTP listeners (use HTTPS only)
- Certificate-based authentication
- Restrict TrustedHosts
- Enable WinRM auditing

**Detection:**

```powershell
# Check WinRM service status
Get-Service WinRM

# Check WinRM listeners
Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate

# Check if HTTP listener exists (should be removed)
Get-ChildItem WSMan:\localhost\Listener | 
    Where-Object {$_.Keys -contains "Transport=HTTP"}

# Check TrustedHosts (should be specific, not *)
Get-Item WSMan:\localhost\Client\TrustedHosts
```

**Audit First:**

```powershell
# Review WinRM usage logs
Get-WinEvent -LogName "Microsoft-Windows-WinRM/Operational" -MaxEvents 100 | 
    Select-Object TimeCreated, Message -First 20

# Identify systems connecting via WinRM
# Plan certificate deployment for HTTPS
```

**Impact Assessment:**

- Identify automation/scripts using WinRM
- Plan certificate deployment for HTTPS listeners
- Test compatibility with management tools (SCCM, monitoring)
- Notify administrators of HTTPS-only requirement

**Mitigation:**

```powershell
# Step 1: Create HTTPS listener with certificate
# First, ensure server has certificate with Server Authentication EKU

# Get certificate thumbprint for WinRM
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | 
    Where-Object {$_.Subject -like "*$env:COMPUTERNAME*" -and $_.EnhancedKeyUsageList -match "Server Authentication"} | 
    Select-Object -First 1

if ($cert) {
    # Create HTTPS listener
    New-WSManInstance -ResourceURI winrm/config/Listener `
        -SelectorSet @{Address="*";Transport="HTTPS"} `
        -ValueSet @{Hostname="$env:COMPUTERNAME.contoso.com";CertificateThumbprint=$cert.Thumbprint}
} else {
    Write-Warning "No suitable certificate found. Request certificate from CA first."
}

# Step 2: Remove HTTP listener
Get-ChildItem WSMan:\localhost\Listener | 
    Where-Object {$_.Keys -contains "Transport=HTTP"} | 
    Remove-Item -Recurse

# Step 3: Restrict TrustedHosts (avoid using *)
# Only add specific servers that need WinRM access
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "dc01.contoso.com,dc02.contoso.com" -Force

# Step 4: Enable WinRM auditing
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service" `
    -Name "LogLevel" -Value 3
# LogLevel: 1=Errors, 2=Warnings, 3=Info (audit all WinRM connections)

# Step 5: Configure firewall (allow HTTPS WinRM, block HTTP)
New-NetFirewallRule -DisplayName "WinRM HTTPS" -Direction Inbound `
    -Protocol TCP -LocalPort 5986 -Action Allow -Enabled True

Disable-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)"
```

**Verification:**

```powershell
# Verify HTTPS listener exists, HTTP removed
Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate
# Should show only HTTPS listener (port 5986), no HTTP (port 5985)

# Test WinRM over HTTPS
Test-WSMan -ComputerName localhost -UseSSL

# Test remote PowerShell session
$cred = Get-Credential
Enter-PSSession -ComputerName DC01 -Credential $cred -UseSSL

# Verify TrustedHosts restricted
Get-Item WSMan:\localhost\Client\TrustedHosts
# Should show specific hosts, not "*"
```

**Rollback:**

```powershell
# Re-enable HTTP listener
New-WSManInstance -ResourceURI winrm/config/Listener `
    -SelectorSet @{Address="*";Transport="HTTP"} `
    -ValueSet @{}

# Reset TrustedHosts
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
```

**Additional WinRM Security:**

```powershell
# Require Kerberos authentication (disable Basic auth)
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
Set-Item WSMan:\localhost\Service\Auth\Kerberos -Value $true

# Disable CredSSP (credential delegation security risk)
Set-Item WSMan:\localhost\Service\Auth\CredSSP -Value $false

# Configure WinRM to use HTTPS by default in PowerShell sessions
$PSSessionOption = New-PSSessionOption -UseSSL -SkipCACheck:$false -SkipCNCheck:$false
```

---

## 5.6 Protocol Security Summary

### Implemented Remediations

This chapter detailed the following protocol security remediations:

| Protocol/Service | Vulnerability | Mitigation | Timeline |
|------------------|---------------|------------|----------|
| NTLM | NTLMv1/LM enabled | Ban NTLMv1, enforce NTLMv2 minimum | 0-7 days |
| RPC | Coercion attacks | Block NTLM outbound from DCs | 0-7 days |
| LDAP | Unsigned binds | Require LDAP signing | 14-21 days |
| LDAPS | No channel binding | Enforce channel binding | 14-21 days |
| ADCS | HTTP enrollment | HTTPS-only enrollment | 14-21 days |
| LLMNR | Name poisoning | Disable LLMNR | 30-60 days |
| NetBIOS | Name poisoning | Disable NetBIOS over TCP/IP | 30-60 days |
| RDP | Insecure config | NLA, High encryption, Restricted Admin | 30-60 days |
| WinRM | HTTP listeners | HTTPS-only, certificate auth | 30-60 days |

### Audit-First Methodology Success

All protocol remediations followed the audit-first approach:
1. ✓ Detection scripts confirmed vulnerabilities
2. ✓ Audit mode enabled to monitor business impact
3. ✓ Impact assessment conducted (48-72 hours typical)
4. ✓ Mitigation implemented with stakeholder approval
5. ✓ Verification scripts confirmed successful remediation
6. ✓ Rollback procedures documented and tested

### PowerShell Automation

Complete PowerShell implementation provided for:
- Detection (confirm vulnerability exists)
- Audit enablement (monitor usage)
- Mitigation (implement fix)
- Verification (confirm success)
- Rollback (restore if needed)

All scripts can be adapted for larger environments using PowerShell remoting and Group Policy.

---

## Summary

This chapter addressed insecure protocol and authentication vulnerabilities through systematic remediation:

- **NTLM:** Banned legacy LM and NTLMv1, restricted NTLM outbound from DCs
- **LDAP:** Required signing and channel binding for directory queries
- **ADCS:** Migrated web enrollment to HTTPS-only
- **Name Resolution:** Disabled LLMNR and NetBIOS poisoning vectors
- **Remote Access:** Hardened RDP and WinRM configurations

All changes implemented using audit-first methodology to ensure business continuity. The next chapter covers configuration hardening and additional security enhancements.

---

[← Previous: Security Configuration Assessment and Risk Analysis](04-risk-assessment.md) | [Next: Configuration Hardening and Security Enhancements →](06-configuration-hardening.md)
