[← Back to Main](../README.md)

# Appendix B: Secure RDP and WinRM Implementation Guide

## Comprehensive Guide to Remote Access Protocol Hardening

This appendix provides detailed implementation guidance for securing Remote Desktop Protocol (RDP) and Windows Remote Management (WinRM) in Active Directory environments.

---

## Table of Contents

1. [Remote Desktop Protocol (RDP) Hardening](#rdp-hardening)
2. [Windows Remote Management (WinRM) Hardening](#winrm-hardening)
3. [Certificate Requirements](#certificate-requirements)
4. [Firewall Configuration](#firewall-configuration)
5. [Monitoring and Logging](#monitoring-and-logging)
6. [Troubleshooting](#troubleshooting)

---

## RDP Hardening

### Overview

Remote Desktop Protocol (RDP) is a critical remote access technology but presents significant security risks if not properly configured. Default RDP configurations lack important security controls.

**Security Risks:**
- Man-in-the-middle attacks via weak encryption
- Credential theft without Network Level Authentication (NLA)
- Brute force attacks against exposed RDP ports
- Pass-the-Hash attacks via unrestricted admin mode

---

### 1. Detection and Current State Assessment

#### Check if RDP is Enabled

```powershell
# Check RDP status on local system
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
# Value 0 = RDP Enabled, Value 1 = RDP Disabled

# Check RDP status on remote computers
$computers = @("DC01", "DC02", "SERVER01")
foreach ($computer in $computers) {
    $rdpStatus = Invoke-Command -ComputerName $computer -ScriptBlock {
        Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
    }
    Write-Host "$computer - RDP Enabled: $($rdpStatus.fDenyTSConnections -eq 0)"
}
```

#### Check Network Level Authentication (NLA) Status

```powershell
# Check if NLA is required
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication"
# Value 0 = NLA Disabled, Value 1 = NLA Enabled (REQUIRED)

# Domain-wide NLA check
$computers = Get-ADComputer -Filter {OperatingSystem -like "*Server*"} | Select-Object -ExpandProperty Name
$nlaReport = @()
foreach ($computer in $computers) {
    try {
        $nla = Invoke-Command -ComputerName $computer -ScriptBlock {
            Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication"
        } -ErrorAction Stop
        $nlaReport += [PSCustomObject]@{
            Computer = $computer
            NLA_Enabled = ($nla.UserAuthentication -eq 1)
            Status = "Success"
        }
    } catch {
        $nlaReport += [PSCustomObject]@{
            Computer = $computer
            NLA_Enabled = "Unknown"
            Status = "Failed: $($_.Exception.Message)"
        }
    }
}
$nlaReport | Format-Table -AutoSize
```

#### Check RDP Encryption Level

```powershell
# Check minimum encryption level
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel"
# Values: 1 = Low, 2 = Client Compatible, 3 = High, 4 = FIPS Compliant
```

#### Check Restricted Admin Mode Status

```powershell
# Check if Restricted Admin mode is available
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -ErrorAction SilentlyContinue
# Value 0 = Enabled, Value 1 or missing = Disabled
```

---

### 2. Audit Current RDP Usage

#### Review RDP Access Logs

```powershell
# Identify RDP logon events (Event ID 4624, LogonType 10)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4624
} -MaxEvents 1000 | Where-Object {
    $_.Properties[8].Value -eq 10  # LogonType 10 = RemoteInteractive (RDP)
} | Select-Object TimeCreated,
    @{N='User';E={$_.Properties[5].Value}},
    @{N='SourceIP';E={$_.Properties[18].Value}},
    @{N='LogonType';E={$_.Properties[8].Value}} | 
Format-Table -AutoSize

# Export to CSV for analysis
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4624
} -MaxEvents 5000 | Where-Object {
    $_.Properties[8].Value -eq 10
} | Select-Object TimeCreated,
    @{N='User';E={$_.Properties[5].Value}},
    @{N='SourceIP';E={$_.Properties[18].Value}} |
Export-Csv -Path "C:\Temp\RDP_Access_Report.csv" -NoTypeInformation
```

#### Identify Servers with RDP Enabled

```powershell
# Scan domain for servers with RDP enabled
$servers = Get-ADComputer -Filter {OperatingSystem -like "*Server*"} | Select-Object -ExpandProperty Name
$rdpEnabledServers = @()

foreach ($server in $servers) {
    try {
        $rdpStatus = Invoke-Command -ComputerName $server -ScriptBlock {
            (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections").fDenyTSConnections
        } -ErrorAction Stop
        
        if ($rdpStatus -eq 0) {
            $rdpEnabledServers += [PSCustomObject]@{
                Server = $server
                RDP_Enabled = $true
            }
        }
    } catch {
        Write-Warning "Failed to query $server"
    }
}

$rdpEnabledServers | Format-Table -AutoSize
Write-Host "Total servers with RDP enabled: $($rdpEnabledServers.Count)"
```

---

### 3. RDP Hardening Implementation

#### 3.1 Enable Network Level Authentication (NLA)

**Why NLA is Critical:**
- Authenticates users before establishing full RDP session
- Prevents unauthenticated enumeration of server information
- Mitigates certain denial-of-service attacks
- Required for Restricted Admin mode

**Implementation via PowerShell:**

```powershell
# Enable NLA on local system
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "UserAuthentication" -Value 1 -Type DWord

# Enable NLA on remote servers via GPO is preferred
# GPO Path: Computer Configuration → Administrative Templates → Windows Components → 
#           Remote Desktop Services → Remote Desktop Session Host → Security
# Setting: Require user authentication for remote connections by using Network Level Authentication
# Value: Enabled
```

**Implementation via Group Policy:**

1. Open Group Policy Management Console (GPMC)
2. Create or edit GPO linked to Servers OU
3. Navigate to:
   - Computer Configuration → Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Session Host → Security
4. Configure: **Require user authentication for remote connections by using Network Level Authentication**
   - Set to: **Enabled**
5. Run `gpupdate /force` on target servers

---

#### 3.2 Set Encryption to High Level

**Implementation:**

```powershell
# Set minimum encryption level to High (3)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "MinEncryptionLevel" -Value 3 -Type DWord

# Via GPO:
# Computer Configuration → Administrative Templates → Windows Components → 
# Remote Desktop Services → Remote Desktop Session Host → Security
# Setting: Set client connection encryption level
# Value: High Level
```

**Encryption Levels:**
- **1 = Low:** Data sent from client to server is encrypted (server to client is not)
- **2 = Client Compatible:** Max key strength supported by client
- **3 = High:** 128-bit encryption in both directions (RECOMMENDED)
- **4 = FIPS Compliant:** FIPS 140-1 validated encryption (if required by compliance)

---

#### 3.3 Enable Restricted Admin Mode

**Purpose:**
- Prevents credential caching on remote system
- Mitigates Pass-the-Hash attacks
- Uses network logon instead of interactive logon

**Enable Restricted Admin Mode:**

```powershell
# Enable Restricted Admin mode
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" `
    -Name "DisableRestrictedAdmin" -Value 0 -PropertyType DWord -Force

# Verify setting
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin"
# Expected: DisableRestrictedAdmin = 0
```

**Using Restricted Admin Mode:**

```powershell
# Connect using Restricted Admin mode
mstsc.exe /restrictedAdmin

# Or from command line
cmdkey /generic:TERMSRV/targetserver /user:DOMAIN\AdminUser /pass:*
mstsc /v:targetserver /restrictedAdmin
```

**Important Notes:**
- Requires NLA to be enabled
- Supported on Windows Server 2012 R2 and later
- May not work with all applications (test before deployment)

---

#### 3.4 Disable Remote Desktop on Domain Controllers (RECOMMENDED)

**Best Practice:**
- Domain Controllers should not allow RDP access
- Use jump servers or Privileged Access Workstations (PAWs) instead
- Reduces attack surface on critical infrastructure

```powershell
# Disable RDP on Domain Controllers
$domainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName

foreach ($dc in $domainControllers) {
    Invoke-Command -ComputerName $dc -ScriptBlock {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
            -Name "fDenyTSConnections" -Value 1 -Type DWord
        
        # Disable firewall rules for RDP
        Disable-NetFirewallRule -DisplayName "Remote Desktop*"
    }
    Write-Host "RDP disabled on $dc"
}
```

**Alternative: Restrict RDP to Specific IP Addresses**

If RDP must remain enabled on DCs, restrict access to jump servers only:

```powershell
# Configure firewall to allow RDP only from jump server (192.168.1.100)
Set-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)" `
    -RemoteAddress "192.168.1.100"

Set-NetFirewallRule -DisplayName "Remote Desktop - User Mode (UDP-In)" `
    -RemoteAddress "192.168.1.100"
```

---

#### 3.5 Configure RDP Timeouts

**Prevent abandoned sessions:**

```powershell
# Set idle session timeout to 15 minutes (900000 ms)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "MaxIdleTime" -Value 900000 -Type DWord

# Set maximum session time to 8 hours (28800000 ms)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "MaxConnectionTime" -Value 28800000 -Type DWord

# Set disconnected session timeout to 5 minutes (300000 ms)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "MaxDisconnectionTime" -Value 300000 -Type DWord
```

**Via Group Policy:**

- Computer Configuration → Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Session Host → Session Time Limits
  - Set time limit for active but idle Remote Desktop Services sessions: **15 minutes**
  - Set time limit for disconnected sessions: **5 minutes**
  - Set time limit for active Remote Desktop Services sessions: **8 hours**

---

### 4. Verification and Testing

```powershell
# Comprehensive RDP security check script
function Test-RDPSecurity {
    param([string]$ComputerName = $env:COMPUTERNAME)
    
    $results = @{}
    
    # Check RDP status
    $rdpEnabled = (Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections").fDenyTSConnections
    }) -eq 0
    $results['RDP_Enabled'] = $rdpEnabled
    
    # Check NLA
    $nlaEnabled = (Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication").UserAuthentication
    }) -eq 1
    $results['NLA_Enabled'] = $nlaEnabled
    
    # Check encryption level
    $encLevel = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel").MinEncryptionLevel
    }
    $results['Encryption_Level'] = $encLevel
    $results['Encryption_Secure'] = ($encLevel -ge 3)
    
    # Check Restricted Admin
    $restrictedAdmin = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        $val = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -ErrorAction SilentlyContinue
        if ($val) { return $val.DisableRestrictedAdmin -eq 0 }
        return $false
    }
    $results['RestrictedAdmin_Enabled'] = $restrictedAdmin
    
    return [PSCustomObject]$results
}

# Test single server
Test-RDPSecurity -ComputerName "SERVER01"

# Test all servers
$allServers = Get-ADComputer -Filter {OperatingSystem -like "*Server*"} | Select-Object -ExpandProperty Name
$securityReport = foreach ($server in $allServers) {
    try {
        Test-RDPSecurity -ComputerName $server
    } catch {
        Write-Warning "Failed to test $server"
    }
}
$securityReport | Format-Table -AutoSize
```

---

## WinRM Hardening

### Overview

Windows Remote Management (WinRM) is Microsoft's implementation of the WS-Management protocol, used for remote PowerShell, server management, and automation.

**Default Security Issues:**
- HTTP listener (port 5985) transmits data in cleartext
- Wildcard TrustedHosts configurations bypass authentication checks
- Insufficient logging of remote management activity

---

### 1. Detection and Current State Assessment

#### Check WinRM Service Status

```powershell
# Check WinRM service
Get-Service WinRM | Select-Object Name, Status, StartType

# Check on remote computers
$computers = @("DC01", "DC02", "SERVER01")
foreach ($computer in $computers) {
    try {
        $svc = Get-Service -Name WinRM -ComputerName $computer -ErrorAction Stop
        Write-Host "$computer - WinRM: $($svc.Status) ($($svc.StartType))"
    } catch {
        Write-Host "$computer - WinRM: Unable to query"
    }
}
```

#### Check WinRM Listeners

```powershell
# Enumerate all WinRM listeners
Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate

# Check for insecure HTTP listeners (should be removed)
Get-ChildItem WSMan:\localhost\Listener | Where-Object {$_.Keys -contains "Transport=HTTP"}

# Check for secure HTTPS listeners (should exist)
Get-ChildItem WSMan:\localhost\Listener | Where-Object {$_.Keys -contains "Transport=HTTPS"}
```

#### Check TrustedHosts Configuration

```powershell
# Check TrustedHosts (should NOT be "*")
Get-Item WSMan:\localhost\Client\TrustedHosts

# Wildcard (*) in TrustedHosts is a CRITICAL security issue
$trustedHosts = (Get-Item WSMan:\localhost\Client\TrustedHosts).Value
if ($trustedHosts -eq "*") {
    Write-Warning "CRITICAL: TrustedHosts is set to wildcard (*) - INSECURE CONFIGURATION"
} else {
    Write-Host "TrustedHosts: $trustedHosts"
}
```

---

### 2. Audit Current WinRM Usage

```powershell
# Review WinRM operational logs
Get-WinEvent -LogName "Microsoft-Windows-WinRM/Operational" -MaxEvents 100 | 
    Select-Object TimeCreated, Id, Message | Format-Table -AutoSize

# Find remote PowerShell sessions (Event ID 4688 with wsmprovhost.exe)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4688  # Process creation
} -MaxEvents 1000 | Where-Object {
    $_.Properties[5].Value -like "*wsmprovhost.exe*"
} | Select-Object TimeCreated,
    @{N='User';E={$_.Properties[1].Value}},
    @{N='Process';E={$_.Properties[5].Value}} |
Format-Table -AutoSize
```

---

### 3. WinRM Hardening Implementation

#### 3.1 Remove HTTP Listeners (Port 5985)

**Critical:** HTTP transmits credentials and data in cleartext over the network.

```powershell
# List all HTTP listeners
$httpListeners = Get-ChildItem WSMan:\localhost\Listener | Where-Object {
    $_.Keys -contains "Transport=HTTP"
}

# Remove each HTTP listener
foreach ($listener in $httpListeners) {
    $listenerPath = $listener.PSPath
    Write-Host "Removing HTTP listener: $listenerPath"
    Remove-Item -Path $listenerPath -Recurse -Force
}

# Verify HTTP listeners removed
Get-ChildItem WSMan:\localhost\Listener | Where-Object {$_.Keys -contains "Transport=HTTP"}
# Should return no results
```

---

#### 3.2 Configure HTTPS Listener with Certificate

**Prerequisites:**
- Valid server authentication certificate issued by trusted CA
- Certificate must have Server Authentication EKU (OID 1.3.6.1.5.5.7.3.1)
- Subject or SAN must match server FQDN

**Step 1: Obtain Certificate**

```powershell
# Request certificate from ADCS using web enrollment or certreq
# Or use existing certificate:
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.Subject -like "*$env:COMPUTERNAME*" -and
    $_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.5.7.3.1"
} | Select-Object -First 1

if ($cert) {
    Write-Host "Found certificate: $($cert.Thumbprint)"
    Write-Host "Subject: $($cert.Subject)"
    Write-Host "Expires: $($cert.NotAfter)"
} else {
    Write-Warning "No suitable certificate found. Request one from ADCS."
}
```

**Step 2: Create HTTPS Listener**

```powershell
# Get certificate thumbprint
$certThumbprint = $cert.Thumbprint
$hostname = "$env:COMPUTERNAME.$env:USERDNSDOMAIN"

# Create HTTPS listener
New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{
    Address = "*"
    Transport = "HTTPS"
} -ValueSet @{
    Hostname = $hostname
    CertificateThumbprint = $certThumbprint
}

# Verify HTTPS listener created
Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate | 
    Where-Object {$_.Transport -eq "HTTPS"}
```

**Step 3: Configure Firewall for HTTPS (Port 5986)**

```powershell
# Enable WinRM HTTPS firewall rule
Enable-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)"

# Or create custom rule with IP restrictions
New-NetFirewallRule -DisplayName "WinRM HTTPS (Custom)" `
    -Direction Inbound `
    -LocalPort 5986 `
    -Protocol TCP `
    -Action Allow `
    -RemoteAddress "192.168.1.0/24" `
    -Profile Domain
```

---

#### 3.3 Restrict TrustedHosts (Remove Wildcards)

**Issue:** TrustedHosts="*" bypasses mutual authentication and allows any computer to connect.

```powershell
# BAD: Wildcard configuration (NEVER DO THIS)
# Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

# GOOD: Explicit list of trusted computers
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "dc01.contoso.com,dc02.contoso.com,jumpserver.contoso.com" -Force

# Or clear TrustedHosts completely (recommended when using Kerberos/certificates)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "" -Force

# Verify configuration
Get-Item WSMan:\localhost\Client\TrustedHosts
```

**Best Practice:** Use Kerberos authentication (default in domain) and leave TrustedHosts empty.

---

#### 3.4 Enable WinRM Logging and Auditing

```powershell
# Enable detailed WinRM logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service" `
    -Name "LogLevel" -Value 3 -Type DWord

# LogLevel values:
# 1 = Errors only
# 2 = Errors and warnings
# 3 = Errors, warnings, and informational (RECOMMENDED)

# Increase WinRM operational log size
wevtutil sl Microsoft-Windows-WinRM/Operational /ms:104857600  # 100 MB

# Enable PowerShell remoting audit policy via GPO
# Computer Configuration → Administrative Templates → Windows Components → 
# Windows PowerShell → Turn on Module Logging
# Turn on PowerShell Script Block Logging
```

---

#### 3.5 Configure WinRM Authentication Methods

```powershell
# Check current authentication settings
Get-WSManInstance -ResourceURI winrm/config/service/auth

# Recommended configuration:
# - Kerberos: Enabled (default in domain, uses mutual authentication)
# - Certificate: Enabled (for workgroup or DMZ scenarios)
# - Basic: Disabled (transmits credentials in Base64, insecure)
# - CredSSP: Disabled (unless explicitly required, vulnerable to credential delegation)

# Disable Basic authentication
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $false

# Disable CredSSP (unless required)
Set-Item -Path WSMan:\localhost\Service\Auth\CredSSP -Value $false

# Verify settings
Get-Item WSMan:\localhost\Service\Auth\*
```

---

### 4. Testing WinRM HTTPS Connectivity

```powershell
# Test WinRM HTTPS from client
Test-WSMan -ComputerName "server01.contoso.com" -UseSSL

# Establish remote PowerShell session using HTTPS
$session = New-PSSession -ComputerName "server01.contoso.com" -UseSSL -Credential (Get-Credential)
Enter-PSSession -Session $session

# Verify connection is using HTTPS
Invoke-Command -Session $session -ScriptBlock {
    Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate | Where-Object {$_.Transport -eq "HTTPS"}
}

# Close session
Remove-PSSession -Session $session
```

---

## Certificate Requirements

### Server Authentication Certificates for HTTPS

**Requirements:**
- Issued by trusted Certificate Authority (internal ADCS or public CA)
- Key Usage: Digital Signature, Key Encipherment
- Enhanced Key Usage: Server Authentication (OID 1.3.6.1.5.5.7.3.1)
- Subject or Subject Alternative Name (SAN) must match server FQDN
- Private key must be exportable (for backup/disaster recovery)

### Request Certificate from ADCS

**Option 1: Web Enrollment**

1. Navigate to: `https://ca01.contoso.com/certsrv`
2. Select **Request a certificate**
3. Select **Advanced certificate request**
4. Choose **Web Server** template
5. Enter FQDN in Common Name field
6. Submit and install

**Option 2: PowerShell (Recommended)**

```powershell
# Request certificate using certreq
$certTemplate = "WebServer"  # Or custom template with Server Authentication EKU
$hostname = "$env:COMPUTERNAME.$env:USERDNSDOMAIN"

# Create certificate request INF file
$infContent = @"
[NewRequest]
Subject = "CN=$hostname"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = TRUE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.1 ; Server Authentication

[RequestAttributes]
CertificateTemplate = "$certTemplate"
"@

# Save INF file
$infContent | Out-File -FilePath "C:\Temp\certrequest.inf" -Encoding ASCII

# Submit certificate request
certreq -new "C:\Temp\certrequest.inf" "C:\Temp\certrequest.req"
certreq -submit -config "CA01.contoso.com\contoso-CA01-CA" "C:\Temp\certrequest.req" "C:\Temp\cert.cer"
certreq -accept "C:\Temp\cert.cer"

# Verify certificate installed
Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*$hostname*"}
```

---

## Firewall Configuration

### RDP Firewall Rules

```powershell
# Review current RDP firewall rules
Get-NetFirewallRule -DisplayName "Remote Desktop*" | Select-Object DisplayName, Enabled, Direction, Action

# Restrict RDP to specific source IP addresses (e.g., jump servers only)
Set-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)" `
    -RemoteAddress "192.168.1.100,192.168.1.101"

Set-NetFirewallRule -DisplayName "Remote Desktop - User Mode (UDP-In)" `
    -RemoteAddress "192.168.1.100,192.168.1.101"

# Disable RDP completely (if not needed)
Disable-NetFirewallRule -DisplayName "Remote Desktop*"
```

### WinRM Firewall Rules

```powershell
# Review WinRM firewall rules
Get-NetFirewallRule -DisplayName "Windows Remote Management*" | 
    Select-Object DisplayName, Enabled, LocalPort, RemoteAddress

# Disable HTTP (port 5985) firewall rule
Disable-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)"

# Enable HTTPS (port 5986) with IP restrictions
Set-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" `
    -Enabled True `
    -RemoteAddress "192.168.1.0/24"
```

---

## Monitoring and Logging

### RDP Monitoring

```powershell
# Monitor successful RDP logons (Event ID 4624, LogonType 10)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4624
} | Where-Object {$_.Properties[8].Value -eq 10} | 
    Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}}, 
    @{N='SourceIP';E={$_.Properties[18].Value}}

# Monitor failed RDP logons (Event ID 4625, LogonType 10)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4625
} | Where-Object {$_.Properties[10].Value -eq 10} | 
    Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}},
    @{N='FailureReason';E={$_.Properties[8].Value}}

# Monitor RDP session disconnect/reconnect (Event IDs 4778, 4779)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4778,4779}
```

### WinRM Monitoring

```powershell
# Monitor WinRM connection attempts
Get-WinEvent -LogName "Microsoft-Windows-WinRM/Operational" | 
    Where-Object {$_.Id -in @(6,7,8,9,10)} | 
    Select-Object TimeCreated, Id, Message

# Event IDs:
# 6 - WSMan operation failed
# 7 - Creating WSMan session
# 8 - Closing WSMan session
# 9 - WSMan received HTTP response
# 10 - WSMan sent HTTP request
```

---

## Troubleshooting

### RDP Troubleshooting

**Issue: Unable to connect via RDP after enabling NLA**

```powershell
# Verify NLA is supported on client
# Client must be Windows Vista SP1 / Windows Server 2008 or later

# Temporarily disable NLA for testing (re-enable afterward)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "UserAuthentication" -Value 0

# Test connection, then re-enable NLA
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "UserAuthentication" -Value 1
```

**Issue: RDP connection fails with certificate errors**

```powershell
# Check RDP certificate
Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices | 
    Select-Object TerminalName, SSLCertificateSHA1Hash

# Replace self-signed certificate with trusted certificate
# Use RDP certificate MMC snap-in or PowerShell
```

### WinRM Troubleshooting

**Issue: Test-WSMan fails with SSL/TLS error**

```powershell
# Check certificate is trusted on client
# Import CA certificate to Trusted Root Certification Authorities

# Test without SSL first
Test-WSMan -ComputerName "server01.contoso.com"

# Then test with SSL
Test-WSMan -ComputerName "server01.contoso.com" -UseSSL
```

**Issue: WinRM HTTPS listener not working**

```powershell
# Verify certificate thumbprint matches listener configuration
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.5.7.3.1"
} | Select-Object -First 1

$listener = Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate | 
    Where-Object {$_.Transport -eq "HTTPS"}

Write-Host "Certificate Thumbprint: $($cert.Thumbprint)"
Write-Host "Listener Thumbprint: $($listener.CertificateThumbprint)"

# If mismatch, recreate listener with correct certificate
```

---

## Complete Hardening Script

### RDP + WinRM Hardening (Combined)

```powershell
# Comprehensive RDP and WinRM hardening script
# Run with administrative privileges

# RDP Hardening
Write-Host "=== RDP Hardening ===" -ForegroundColor Green

# Enable NLA
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "UserAuthentication" -Value 1
Write-Host "[OK] NLA Enabled"

# Set encryption to High
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "MinEncryptionLevel" -Value 3
Write-Host "[OK] Encryption set to High"

# Enable Restricted Admin Mode
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" `
    -Name "DisableRestrictedAdmin" -Value 0 -PropertyType DWord -Force
Write-Host "[OK] Restricted Admin Mode Enabled"

# Configure timeouts
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "MaxIdleTime" -Value 900000  # 15 minutes
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "MaxDisconnectionTime" -Value 300000  # 5 minutes
Write-Host "[OK] RDP timeouts configured"

# WinRM Hardening
Write-Host "`n=== WinRM Hardening ===" -ForegroundColor Green

# Remove HTTP listeners
$httpListeners = Get-ChildItem WSMan:\localhost\Listener | Where-Object {
    $_.Keys -contains "Transport=HTTP"
}
foreach ($listener in $httpListeners) {
    Remove-Item -Path $listener.PSPath -Recurse -Force
}
Write-Host "[OK] HTTP listeners removed"

# Disable Basic authentication
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $false
Write-Host "[OK] Basic authentication disabled"

# Clear TrustedHosts
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "" -Force
Write-Host "[OK] TrustedHosts cleared"

# Enable detailed logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service" `
    -Name "LogLevel" -Value 3
Write-Host "[OK] WinRM logging enabled"

Write-Host "`n=== Hardening Complete ===" -ForegroundColor Green
Write-Host "Next steps:"
Write-Host "1. Configure WinRM HTTPS listener with certificate"
Write-Host "2. Configure firewall rules to restrict RDP/WinRM access"
Write-Host "3. Test connectivity from management workstations"
```

---

## Summary Checklist

### RDP Hardening Checklist

- [ ] Network Level Authentication (NLA) enabled
- [ ] Minimum encryption level set to High (3)
- [ ] Restricted Admin Mode enabled
- [ ] Idle session timeout configured (15 minutes)
- [ ] Disconnected session timeout configured (5 minutes)
- [ ] Firewall restricted to specific source IPs (or RDP disabled on DCs)
- [ ] RDP access logging enabled and monitored

### WinRM Hardening Checklist

- [ ] HTTP listeners removed (port 5985 closed)
- [ ] HTTPS listener configured with valid certificate (port 5986)
- [ ] TrustedHosts cleared or restricted to specific FQDNs
- [ ] Basic authentication disabled
- [ ] CredSSP disabled (unless explicitly required)
- [ ] WinRM operational logging enabled
- [ ] Firewall restricted to management subnets
- [ ] PowerShell script block logging enabled

---

[← Back to Main](../README.md)
