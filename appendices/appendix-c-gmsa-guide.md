[← Back to Main](../README.md)

# Appendix C: Group Managed Service Accounts (gMSA) Implementation Guide

## Comprehensive gMSA Deployment and Management

Group Managed Service Accounts (gMSA) provide automatic password management and simplified Service Principal Name (SPN) administration for service accounts across multiple servers in Active Directory environments.

---

## Table of Contents

1. [Overview and Benefits](#overview-and-benefits)
2. [Prerequisites and Requirements](#prerequisites-and-requirements)
3. [Detection and Assessment](#detection-and-assessment)
4. [gMSA Implementation](#gmsa-implementation)
5. [Service Migration to gMSA](#service-migration)
6. [Verification and Testing](#verification-and-testing)
7. [Troubleshooting](#troubleshooting)
8. [Best Practices](#best-practices)

---

## Overview and Benefits

### What is gMSA?

Group Managed Service Accounts (gMSA) are a special type of Active Directory account introduced in Windows Server 2012 that provides:

- **Automatic password management** - Passwords are 240 characters, randomly generated, and automatically rotated every 30 days
- **No password expiration issues** - Services never fail due to expired passwords
- **Simplified SPN management** - SPNs are automatically managed by Active Directory
- **Multi-server support** - Same gMSA can be used across multiple servers
- **Enhanced security** - Eliminates password sharing and manual password changes

### gMSA vs. Traditional Service Accounts

| Feature | Traditional Service Account | gMSA |
|---------|----------------------------|------|
| **Password Management** | Manual | Automatic (240 characters, rotated every 30 days) |
| **Password Knowledge** | Admins know/set password | No admin knows password |
| **Multi-server Support** | Same password shared | Same account, automatic sync |
| **SPN Management** | Manual setspn commands | Automatic |
| **Password Expiration** | Can cause service failures | Never expires |
| **Credential Theft Risk** | Higher (weak/static passwords) | Lower (240-char random, auto-rotated) |
| **Kerberos Support** | Yes (with manual SPN setup) | Yes (automatic) |
| **Scheduled Tasks** | Supported | Limited support (standalone gMSA only) |

### Security Benefits

1. **Eliminates weak service account passwords** - No more "Password123" or "ServiceAccount2023"
2. **Prevents password sharing** - Each service can have dedicated gMSA
3. **Mitigates credential dumping attacks** - 240-character passwords extremely difficult to crack
4. **Reduces lateral movement risk** - Compromised password quickly rotates automatically
5. **Simplifies compliance** - Automatic password rotation meets policy requirements

---

## Prerequisites and Requirements

### Forest and Domain Requirements

- **Forest Functional Level:** Windows Server 2012 or higher
- **Domain Functional Level:** Windows Server 2012 or higher
- **Domain Controllers:** At least one Windows Server 2012 or higher DC

### Server Requirements

Servers hosting services using gMSA must run:
- Windows Server 2012 or later
- Windows 8.1 / Windows 10 or later (for client systems)

### Required PowerShell Module

```powershell
# Verify Active Directory PowerShell module is installed
Get-Module -ListAvailable -Name ActiveDirectory

# If not installed, add RSAT-AD-PowerShell feature
Install-WindowsFeature RSAT-AD-PowerShell
```

### Permissions Required

To create and manage gMSAs, you need:
- Membership in **Domain Admins** or delegated permissions to create service accounts
- Permissions to modify **CN=System,DC=contoso,DC=com** to create KDS root key

---

## Detection and Assessment

### Check Forest/Domain Functional Level

```powershell
# Check forest functional level
(Get-ADForest).ForestMode
# Required: Windows2012Forest or higher

# Check domain functional level
(Get-ADDomain).DomainMode
# Required: Windows2012Domain or higher

# If levels are too low, raise them (IRREVERSIBLE):
# Set-ADForestMode -Identity contoso.com -ForestMode Windows2012Forest
# Set-ADDomainMode -Identity contoso.com -DomainMode Windows2012Domain
```

### Check KDS Root Key Status

```powershell
# Check if KDS (Key Distribution Service) root key exists
Get-KdsRootKey

# If no keys exist, gMSA cannot be created (output will be empty)
# If keys exist, verify the root key is valid:
$kdsKey = Get-KdsRootKey
if ($kdsKey) {
    Write-Host "KDS Root Key exists"
    Write-Host "Created: $($kdsKey.EffectiveTime)"
    Write-Host "GUID: $($kdsKey.KeyId)"
} else {
    Write-Warning "No KDS Root Key found - must create before deploying gMSA"
}
```

### Identify Candidate Service Accounts for Migration

```powershell
# Find current service accounts (accounts with SPNs)
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName,LastLogonDate,PasswordLastSet | 
    Select-Object Name, SamAccountName, ServicePrincipalName, LastLogonDate, PasswordLastSet | 
    Format-Table -AutoSize

# Identify services running as domain accounts on servers
$servers = @("SERVER01", "SERVER02", "SQLSERVER01")
foreach ($server in $servers) {
    Write-Host "`n=== Services on $server ===" -ForegroundColor Green
    Get-WmiObject Win32_Service -ComputerName $server | 
        Where-Object {$_.StartName -like "*\*" -and $_.StartName -notlike "*LocalSystem*"} | 
        Select-Object Name, DisplayName, StartName, State | 
        Format-Table -AutoSize
}

# Export service account inventory
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties * | 
    Select-Object Name, SamAccountName, ServicePrincipalName, Enabled, PasswordLastSet, PasswordNeverExpires |
    Export-Csv -Path "C:\Temp\ServiceAccount_Inventory.csv" -NoTypeInformation
```

### Check Current gMSA Deployment Status

```powershell
# List existing gMSAs in domain
Get-ADServiceAccount -Filter * | Select-Object Name, DNSHostName, Enabled, DistinguishedName

# Check if any servers are already using gMSA
Get-ADServiceAccount -Filter * | ForEach-Object {
    $gmsa = $_
    $principals = Get-ADServiceAccount -Identity $gmsa.Name -Properties PrincipalsAllowedToRetrieveManagedPassword |
        Select-Object -ExpandProperty PrincipalsAllowedToRetrieveManagedPassword
    
    [PSCustomObject]@{
        gMSA_Name = $gmsa.Name
        Allowed_Principals = ($principals -join ", ")
    }
} | Format-Table -AutoSize
```

---

## gMSA Implementation

### Step 1: Create KDS Root Key (One-Time Setup)

**IMPORTANT:** The KDS root key must be created before any gMSAs can be deployed. This is a one-time forest-level configuration.

```powershell
# Create KDS root key (production - effective after 10 hours)
Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))

# For testing/lab (effective immediately - NOT for production)
# Add-KdsRootKey -EffectiveImmediately

# Verify KDS root key creation
Get-KdsRootKey | Select-Object KeyId, EffectiveTime, CreationTime

# Expected output: KeyId with EffectiveTime 10 hours in the past
```

**Why 10 hours?** Active Directory replication needs time to propagate the KDS root key to all domain controllers. The 10-hour wait ensures all DCs have the key before gMSAs are created.

**In Production:**
- Create KDS root key at least 10 hours before gMSA deployment
- Verify replication completes across all DCs
- Plan gMSA creation for next business day

---

### Step 2: Create Security Group for gMSA Authorization

Create an AD security group containing the computers/servers that are allowed to retrieve the gMSA password.

```powershell
# Create security group for web servers
New-ADGroup -Name "gMSA-WebServers-Authorized" `
    -GroupScope DomainLocal `
    -GroupCategory Security `
    -Path "OU=Groups,DC=contoso,DC=com" `
    -Description "Computers authorized to use gMSA for web application services"

# Add member servers to the group
Add-ADGroupMember -Identity "gMSA-WebServers-Authorized" -Members "WEBSERVER01$","WEBSERVER02$"

# Verify group membership
Get-ADGroupMember -Identity "gMSA-WebServers-Authorized" | Select-Object Name, SamAccountName
```

**Note:** Computer accounts end with `$` - e.g., `WEBSERVER01$`

---

### Step 3: Create gMSA Account

```powershell
# Create gMSA for IIS application pool
New-ADServiceAccount -Name "gmsa-webapp" `
    -DNSHostName "gmsa-webapp.contoso.com" `
    -PrincipalsAllowedToRetrieveManagedPassword "gMSA-WebServers-Authorized" `
    -Description "gMSA for web application service on WEBSERVER01 and WEBSERVER02" `
    -Enabled $true

# Verify gMSA creation
Get-ADServiceAccount -Identity "gmsa-webapp" -Properties * | 
    Select-Object Name, DNSHostName, Enabled, PrincipalsAllowedToRetrieveManagedPassword
```

**Parameters Explained:**
- **Name:** gMSA account name (appears as `gmsa-webapp$` in AD)
- **DNSHostName:** Fully qualified DNS name for Kerberos SPN registration
- **PrincipalsAllowedToRetrieveManagedPassword:** Group or computer accounts allowed to use this gMSA
- **Enabled:** Set to `$true` to activate immediately

---

### Step 4: Set Service Principal Names (SPNs) - If Required

For most services, SPNs are automatically managed. For custom applications, you may need to manually register SPNs.

```powershell
# Check current SPNs on gMSA
Get-ADServiceAccount -Identity "gmsa-webapp" -Properties ServicePrincipalNames | 
    Select-Object -ExpandProperty ServicePrincipalNames

# Add custom SPN if needed
Set-ADServiceAccount -Identity "gmsa-webapp" -ServicePrincipalNames @{Add="HTTP/webapp.contoso.com"}

# Add multiple SPNs
Set-ADServiceAccount -Identity "gmsa-webapp" -ServicePrincipalNames @{Add="HTTP/webapp.contoso.com","HTTP/webapp"}

# Verify SPNs registered
Get-ADServiceAccount -Identity "gmsa-webapp" -Properties ServicePrincipalNames | 
    Select-Object Name, -ExpandProperty ServicePrincipalNames
```

**Common SPN Formats:**
- HTTP services: `HTTP/hostname.domain.com`
- SQL Server: `MSSQLSvc/sqlserver.domain.com:1433`
- Custom apps: `AppName/hostname.domain.com`

---

## Service Migration to gMSA

### Step 1: Install gMSA on Target Server

Before configuring a service to use gMSA, the gMSA must be "installed" on the target server.

```powershell
# Run on the server that will use the gMSA (e.g., WEBSERVER01)

# Test if server can retrieve gMSA password
Test-ADServiceAccount -Identity "gmsa-webapp"
# Expected output: True

# If Test returns False, check:
# 1. Server is member of PrincipalsAllowedToRetrieveManagedPassword group
# 2. KDS root key exists and is effective
# 3. Server has rebooted since being added to authorization group

# Install gMSA on the server
Install-ADServiceAccount -Identity "gmsa-webapp"

# Verify installation
Get-ADServiceAccount -Identity "gmsa-webapp"
```

---

### Step 2: Configure Service to Use gMSA

#### Option A: Windows Service Configuration (GUI)

1. Open **Services** (`services.msc`)
2. Right-click service → **Properties**
3. Navigate to **Log On** tab
4. Select **This account**
5. Enter: `CONTOSO\gmsa-webapp$` (note the `$` at the end)
6. **Leave password fields EMPTY**
7. Click **OK**

#### Option B: Windows Service Configuration (PowerShell)

```powershell
# Configure service to use gMSA
$serviceName = "W3SVC"  # Example: IIS World Wide Web Publishing Service
$gmsaAccount = "CONTOSO\gmsa-webapp$"

# Stop service
Stop-Service -Name $serviceName -Force

# Change service logon account
$service = Get-WmiObject Win32_Service -Filter "Name='$serviceName'"
$result = $service.Change($null, $null, $null, $null, $null, $null, $gmsaAccount, $null, $null, $null, $null)

if ($result.ReturnValue -eq 0) {
    Write-Host "[OK] Service $serviceName configured to use $gmsaAccount" -ForegroundColor Green
} else {
    Write-Warning "Failed to configure service. Return code: $($result.ReturnValue)"
}

# Start service
Start-Service -Name $serviceName

# Verify service is running
Get-Service -Name $serviceName | Select-Object Name, Status, StartName
```

#### Option C: IIS Application Pool Configuration

```powershell
# Configure IIS Application Pool to use gMSA
Import-Module WebAdministration

$appPoolName = "DefaultAppPool"
$gmsaAccount = "CONTOSO\gmsa-webapp$"

# Stop app pool
Stop-WebAppPool -Name $appPoolName

# Set identity to gMSA
Set-ItemProperty "IIS:\AppPools\$appPoolName" -Name processModel.identityType -Value 3  # SpecificUser
Set-ItemProperty "IIS:\AppPools\$appPoolName" -Name processModel.userName -Value $gmsaAccount
Set-ItemProperty "IIS:\AppPools\$appPoolName" -Name processModel.password -Value ""  # Empty password

# Start app pool
Start-WebAppPool -Name $appPoolName

# Verify configuration
Get-ItemProperty "IIS:\AppPools\$appPoolName" -Name processModel | 
    Select-Object userName, identityType

# Check app pool status
Get-WebAppPoolState -Name $appPoolName
```

#### Option D: SQL Server Service Configuration

```powershell
# For SQL Server, use SQL Server Configuration Manager or PowerShell

# PowerShell method (requires SQL Server PowerShell module)
Import-Module SqlServer

$serverInstance = "SQLSERVER01"
$serviceName = "MSSQLSERVER"  # Default instance, or "MSSQL$INSTANCENAME" for named instance
$gmsaAccount = "CONTOSO\gmsa-sqlserver$"

# Change SQL Server service account
Set-Service -Name $serviceName -StartupType Automatic -ErrorAction Stop
Stop-Service -Name $serviceName -Force

# Configure service
$service = Get-WmiObject Win32_Service -Filter "Name='$serviceName'"
$service.Change($null, $null, $null, $null, $null, $null, $gmsaAccount, $null, $null, $null, $null)

# Grant necessary permissions to gMSA
# SQL Server service requires local admin rights on SQL Server host (typically)

Start-Service -Name $serviceName
```

---

### Step 3: Grant Necessary Permissions to gMSA

gMSAs may require additional permissions depending on the service:

#### File System Permissions

```powershell
# Grant gMSA read access to web application files
$path = "C:\inetpub\wwwroot\MyWebApp"
$gmsaAccount = "CONTOSO\gmsa-webapp$"

$acl = Get-Acl -Path $path
$permission = "CONTOSO\gmsa-webapp$", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.SetAccessRule($accessRule)
Set-Acl -Path $path -AclObject $acl

# Verify permissions
Get-Acl -Path $path | Select-Object -ExpandProperty Access | 
    Where-Object {$_.IdentityReference -like "*gmsa-webapp*"}
```

#### SQL Server Permissions

```powershell
# Grant gMSA access to SQL Server database
# Run on SQL Server using SQL authentication or Windows auth

sqlcmd -S SQLSERVER01 -E -Q "CREATE LOGIN [CONTOSO\gmsa-sqlapp$] FROM WINDOWS;"
sqlcmd -S SQLSERVER01 -E -Q "USE [MyDatabase]; CREATE USER [CONTOSO\gmsa-sqlapp$] FOR LOGIN [CONTOSO\gmsa-sqlapp$];"
sqlcmd -S SQLSERVER01 -E -Q "USE [MyDatabase]; ALTER ROLE db_datareader ADD MEMBER [CONTOSO\gmsa-sqlapp$];"
sqlcmd -S SQLSERVER01 -E -Q "USE [MyDatabase]; ALTER ROLE db_datawriter ADD MEMBER [CONTOSO\gmsa-sqlapp$];"
```

#### Registry Permissions (If Required)

```powershell
# Grant gMSA registry access (example: application configuration keys)
$regPath = "HKLM:\SOFTWARE\MyApplication"
$gmsaAccount = "CONTOSO\gmsa-webapp$"

$acl = Get-Acl -Path $regPath
$permission = $gmsaAccount, "ReadKey", "Allow"
$rule = New-Object System.Security.AccessControl.RegistryAccessRule $permission
$acl.SetAccessRule($rule)
Set-Acl -Path $regPath -AclObject $acl
```

---

## Verification and Testing

### Test gMSA Installation and Functionality

```powershell
# === ON TARGET SERVER (e.g., WEBSERVER01) ===

# Test if gMSA password can be retrieved
Test-ADServiceAccount -Identity "gmsa-webapp"
# Expected: True

# Verify gMSA is installed on local server
Get-ADServiceAccount -Identity "gmsa-webapp"

# Check service is running with gMSA
Get-Service -Name "W3SVC" | Select-Object Name, Status, StartName
# StartName should show: CONTOSO\gmsa-webapp$

# Test Kerberos authentication
klist get HTTP/webapp.contoso.com
# Should successfully obtain Kerberos ticket
```

### Verify Password Rotation

```powershell
# Check password last set date
Get-ADServiceAccount -Identity "gmsa-webapp" -Properties PasswordLastSet | 
    Select-Object Name, PasswordLastSet

# gMSA passwords rotate every 30 days automatically
# PasswordLastSet should update automatically
```

### Test Service Functionality

```powershell
# Restart service to ensure it starts correctly with gMSA
Restart-Service -Name "W3SVC" -Force

# Check service status
Get-Service -Name "W3SVC" | Select-Object Name, Status, StartName

# Test application functionality (example: web app)
Invoke-WebRequest -Uri "http://webapp.contoso.com" -UseDefaultCredentials
```

### Validate Kerberos SPNs

```powershell
# Verify SPNs are registered correctly
Get-ADServiceAccount -Identity "gmsa-webapp" -Properties ServicePrincipalNames | 
    Select-Object -ExpandProperty ServicePrincipalNames

# Check for duplicate SPNs (should return no results)
setspn -X -F

# Query specific SPN
setspn -Q HTTP/webapp.contoso.com
# Should return gMSA account as the owner
```

---

## Troubleshooting

### Issue 1: Test-ADServiceAccount Returns False

**Symptoms:**
```powershell
Test-ADServiceAccount -Identity "gmsa-webapp"
# Returns: False
```

**Possible Causes and Solutions:**

1. **Server not in PrincipalsAllowedToRetrieveManagedPassword group**

```powershell
# Check group membership
Get-ADGroupMember -Identity "gMSA-WebServers-Authorized" | 
    Where-Object {$_.Name -like "*WEBSERVER01*"}

# Add server to group
Add-ADGroupMember -Identity "gMSA-WebServers-Authorized" -Members "WEBSERVER01$"

# IMPORTANT: Reboot server after adding to group
Restart-Computer -Force
```

2. **KDS root key not yet effective**

```powershell
# Check KDS root key effective time
Get-KdsRootKey | Select-Object EffectiveTime

# If EffectiveTime is in the future, wait until effective
# Or create a new key with -EffectiveImmediately (lab only)
```

3. **Time synchronization issues**

```powershell
# Verify time sync with domain controller
w32tm /query /status
w32tm /resync /force

# Check time difference
$dcTime = Invoke-Command -ComputerName DC01 -ScriptBlock {Get-Date}
$localTime = Get-Date
$timeDiff = ($localTime - $dcTime).TotalSeconds
Write-Host "Time difference: $timeDiff seconds"
# Should be within 5 minutes (300 seconds)
```

---

### Issue 2: Service Fails to Start with gMSA

**Symptoms:**
- Service stops immediately after starting
- Event Viewer shows "Logon failure" errors

**Solutions:**

1. **Verify gMSA account format includes `$`**

```powershell
# Correct format: CONTOSO\gmsa-webapp$
# Incorrect: CONTOSO\gmsa-webapp (missing $)

Get-Service -Name "W3SVC" | Select-Object StartName
# Should show: CONTOSO\gmsa-webapp$
```

2. **Check password field is empty**

When configuring service, password must be blank. gMSA manages passwords automatically.

3. **Verify gMSA has required permissions**

```powershell
# Grant "Log on as a service" right via GPO or local policy
# Computer Configuration → Windows Settings → Security Settings → 
# Local Policies → User Rights Assignment → Log on as a service

# Add gMSA to local policy (temporary troubleshooting)
# Use secpol.msc → Local Policies → User Rights Assignment → Log on as a service
```

4. **Check service dependencies**

```powershell
Get-Service -Name "W3SVC" -DependentServices
Get-Service -Name "W3SVC" -RequiredServices

# Ensure all dependent services are running
```

---

### Issue 3: Kerberos Authentication Failures

**Symptoms:**
- NTLM fallback instead of Kerberos
- Event ID 4768 or 4769 failures in Security log

**Solutions:**

1. **Verify SPNs are registered correctly**

```powershell
# Check SPNs on gMSA
Get-ADServiceAccount -Identity "gmsa-webapp" -Properties ServicePrincipalNames | 
    Select-Object -ExpandProperty ServicePrincipalNames

# Check for duplicate SPNs
setspn -X -F

# Register missing SPN
Set-ADServiceAccount -Identity "gmsa-webapp" -ServicePrincipalNames @{Add="HTTP/webapp.contoso.com"}
```

2. **Check DNS resolution**

```powershell
# Verify DNS name resolves correctly
Resolve-DnsName -Name "webapp.contoso.com"

# Check PTR (reverse DNS) record exists
Resolve-DnsName -Name "192.168.1.100" -Type PTR
```

3. **Verify Kerberos delegation settings**

```powershell
# Check if gMSA is allowed to delegate
Get-ADServiceAccount -Identity "gmsa-webapp" -Properties TrustedForDelegation,TrustedToAuthForDelegation

# Enable constrained delegation if needed
Set-ADServiceAccount -Identity "gmsa-webapp" -TrustedForDelegation $true
```

---

### Issue 4: gMSA Cannot Be Installed on Server

**Error:** "Install-ADServiceAccount : Cannot install service account"

**Solutions:**

1. **Verify server is authorized**

```powershell
Get-ADServiceAccount -Identity "gmsa-webapp" -Properties PrincipalsAllowedToRetrieveManagedPassword | 
    Select-Object -ExpandProperty PrincipalsAllowedToRetrieveManagedPassword

# Ensure server computer account or group is listed
```

2. **Check AD replication**

```powershell
# Verify gMSA has replicated to all DCs
repadmin /showrepl

# Force replication if needed
repadmin /syncall /AdeP
```

3. **Verify PowerShell module**

```powershell
# Ensure ActiveDirectory module is loaded
Import-Module ActiveDirectory

# Check module version
Get-Module ActiveDirectory | Select-Object Name, Version
```

---

## Best Practices

### 1. Naming Conventions

Use clear, descriptive names for gMSAs:

```
Format: gmsa-<service>-<purpose>

Examples:
- gmsa-iis-webapp
- gmsa-sql-reporting
- gmsa-svc-backup
- gmsa-app-scheduler
```

### 2. Authorization Group Strategy

Create dedicated groups per service type:

```powershell
# Example authorization groups
New-ADGroup -Name "gMSA-WebServers-Authorized" -GroupScope DomainLocal -GroupCategory Security
New-ADGroup -Name "gMSA-SQLServers-Authorized" -GroupScope DomainLocal -GroupCategory Security
New-ADGroup -Name "gMSA-AppServers-Authorized" -GroupScope DomainLocal -GroupCategory Security
```

Benefits:
- Easier management (add/remove servers from group)
- Clear audit trail
- Supports multiple servers using same gMSA

### 3. Documentation and Inventory

Maintain a gMSA inventory spreadsheet:

| gMSA Name | Purpose | Authorized Servers | SPNs | Created Date | Owner |
|-----------|---------|-------------------|------|--------------|-------|
| gmsa-iis-webapp | IIS App Pool for WebApp | WEBSERVER01, WEBSERVER02 | HTTP/webapp.contoso.com | 2025-12-01 | IT Team |
| gmsa-sql-reports | SQL Reporting Service | SQLSERVER01 | MSSQLSvc/sqlserver01:1433 | 2025-12-05 | DBA Team |

### 4. Least Privilege Principle

Grant gMSAs only necessary permissions:

```powershell
# BAD: Adding gMSA to Domain Admins
# Add-ADGroupMember -Identity "Domain Admins" -Members "gmsa-webapp$"

# GOOD: Grant specific file/registry permissions only
$path = "C:\AppData"
$acl = Get-Acl $path
$permission = "CONTOSO\gmsa-webapp$", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.SetAccessRule($accessRule)
Set-Acl $path $acl
```

### 5. Regular Auditing

Monitor gMSA usage quarterly:

```powershell
# List all gMSAs and their authorized principals
Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword | 
    Select-Object Name, DNSHostName, Enabled, @{
        N='AuthorizedPrincipals'
        E={($_.PrincipalsAllowedToRetrieveManagedPassword | ForEach-Object {(Get-ADObject $_).Name}) -join ", "}
    } | Format-Table -AutoSize

# Check for orphaned gMSAs (no authorized principals)
Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword | 
    Where-Object {$_.PrincipalsAllowedToRetrieveManagedPassword.Count -eq 0} | 
    Select-Object Name
```

### 6. Change Management

When decommissioning servers:

```powershell
# Remove server from gMSA authorization group
Remove-ADGroupMember -Identity "gMSA-WebServers-Authorized" -Members "OLDSERVER01$" -Confirm:$false

# If gMSA no longer needed, disable it
Set-ADServiceAccount -Identity "gmsa-oldapp" -Enabled $false

# After 90 days with no issues, delete gMSA
Remove-ADServiceAccount -Identity "gmsa-oldapp" -Confirm:$false
```

### 7. Security Monitoring

Monitor gMSA authentication events:

```powershell
# Monitor Event ID 4624 (Successful logon) for gMSA accounts
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | 
    Where-Object {$_.Properties[5].Value -like "*gmsa-*"} | 
    Select-Object TimeCreated, @{N='Account';E={$_.Properties[5].Value}}, 
    @{N='LogonType';E={$_.Properties[8].Value}}, @{N='SourceIP';E={$_.Properties[18].Value}}

# Alert on unexpected gMSA usage from unauthorized systems
```

---

## Complete gMSA Deployment Script

```powershell
<#
.SYNOPSIS
    Complete gMSA deployment script for web application service
.DESCRIPTION
    Creates gMSA, authorization group, and configures IIS App Pool
.NOTES
    Run on Domain Controller with Domain Admin privileges
#>

# Configuration
$gmsaName = "gmsa-webapp"
$dnsHostName = "gmsa-webapp.contoso.com"
$authGroupName = "gMSA-WebServers-Authorized"
$authorizedServers = @("WEBSERVER01", "WEBSERVER02")
$appPoolName = "DefaultAppPool"

# Step 1: Verify KDS root key exists
Write-Host "=== Checking KDS Root Key ===" -ForegroundColor Green
$kdsKey = Get-KdsRootKey
if (-not $kdsKey) {
    Write-Host "[ACTION REQUIRED] Creating KDS root key (effective in 10 hours)" -ForegroundColor Yellow
    Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
    Write-Host "[WARNING] Wait 10 hours before proceeding with gMSA creation" -ForegroundColor Yellow
    exit
} else {
    Write-Host "[OK] KDS root key exists" -ForegroundColor Green
}

# Step 2: Create authorization group
Write-Host "`n=== Creating Authorization Group ===" -ForegroundColor Green
try {
    New-ADGroup -Name $authGroupName -GroupScope DomainLocal -GroupCategory Security `
        -Path "OU=Groups,DC=contoso,DC=com" -Description "Servers authorized to use $gmsaName"
    Write-Host "[OK] Group $authGroupName created" -ForegroundColor Green
} catch {
    Write-Host "[INFO] Group $authGroupName already exists" -ForegroundColor Yellow
}

# Step 3: Add servers to authorization group
Write-Host "`n=== Adding Servers to Authorization Group ===" -ForegroundColor Green
foreach ($server in $authorizedServers) {
    Add-ADGroupMember -Identity $authGroupName -Members "$server$" -ErrorAction SilentlyContinue
    Write-Host "[OK] Added $server to $authGroupName" -ForegroundColor Green
}

# Step 4: Create gMSA
Write-Host "`n=== Creating gMSA ===" -ForegroundColor Green
try {
    New-ADServiceAccount -Name $gmsaName `
        -DNSHostName $dnsHostName `
        -PrincipalsAllowedToRetrieveManagedPassword $authGroupName `
        -Enabled $true
    Write-Host "[OK] gMSA $gmsaName created" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to create gMSA: $_" -ForegroundColor Red
    exit
}

# Step 5: Verify gMSA creation
$gmsa = Get-ADServiceAccount -Identity $gmsaName -Properties *
Write-Host "`n=== gMSA Details ===" -ForegroundColor Green
Write-Host "Name: $($gmsa.Name)"
Write-Host "DNS Host Name: $($gmsa.DNSHostName)"
Write-Host "Enabled: $($gmsa.Enabled)"
Write-Host "Authorized Principals: $($gmsa.PrincipalsAllowedToRetrieveManagedPassword)"

Write-Host "`n=== Next Steps ===" -ForegroundColor Green
Write-Host "1. Reboot authorized servers: $($authorizedServers -join ', ')"
Write-Host "2. On each server, run: Install-ADServiceAccount -Identity $gmsaName"
Write-Host "3. Configure service/app pool to use: CONTOSO\$gmsaName`$"
Write-Host "4. Leave password blank when configuring service"
```

---

## Summary Checklist

### Pre-Deployment Checklist

- [ ] Forest functional level is Windows Server 2012 or higher
- [ ] Domain functional level is Windows Server 2012 or higher
- [ ] KDS root key created and effective (10 hours minimum)
- [ ] Service account inventory completed
- [ ] Migration plan documented

### gMSA Creation Checklist

- [ ] Authorization group created
- [ ] Member servers added to authorization group
- [ ] gMSA created with correct DNSHostName
- [ ] SPNs registered (if required)
- [ ] gMSA enabled in Active Directory

### Server Configuration Checklist

- [ ] Server rebooted after being added to authorization group
- [ ] Test-ADServiceAccount returns True
- [ ] Install-ADServiceAccount completed successfully
- [ ] Service configured with gMSA account (DOMAIN\gMSA$)
- [ ] Password field left blank
- [ ] Service started successfully
- [ ] Application functionality tested

### Post-Deployment Checklist

- [ ] gMSA inventory documentation updated
- [ ] Monitoring alerts configured
- [ ] Permissions granted (filesystem, registry, database)
- [ ] Service tested for 48-72 hours
- [ ] Old service account disabled (after 30-day observation period)
- [ ] Old service account deleted (after 90 days)

---

[← Back to Main](../README.md)

---

## Resources

- Group Managed Service Accounts overview: https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview
