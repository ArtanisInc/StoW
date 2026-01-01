# Windows Setup Guide for StoW

Complete setup guide for Windows endpoints to enable Sigma rule detection.

## Overview

StoW converts Sigma rules for multiple Windows event sources:

| Source | Rules | Setup |
|--------|-------|-------|
| **Sysmon** | ~3,900 | Install Sysmon (required) |
| **Built-in Channels** | ~50 | Enable channels + Configure agent |
| **Security/System/App** | ~240 | EventID-based (183 Security rules supported) |

**Primary focus:** Sysmon for comprehensive detection coverage.

---

## 1. Sysmon Setup (Required for 3,900+ rules)

### Install Sysmon

```powershell
# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive Sysmon.zip -DestinationPath C:\Tools\Sysmon

# Download SwiftOnSecurity config (recommended starting point)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Tools\Sysmon\sysmonconfig.xml"

# Install Sysmon with config
C:\Tools\Sysmon\Sysmon64.exe -accepteula -i C:\Tools\Sysmon\sysmonconfig.xml
```

### Verify Sysmon Installation

```powershell
# Check service
Get-Service Sysmon64

# Check event log
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

---

## 2. Built-in Windows Channels Setup

### Channels Overview

| Channel | Default State | Rules | Setup Required |
|---------|---------------|-------|----------------|
| **DriverFrameworks** | ❌ Disabled | 1 | Enable + Configure agent |
| **CodeIntegrity** | ✅ Enabled | 10 | Configure agent only |
| **Firewall** | ✅ Enabled | 8 | Configure agent only |
| **BITS-Client** | ✅ Enabled | 7 | Configure agent only |
| **DNS-Client** | ✅ Enabled | 6 | Configure agent only |
| **NTLM** | ❌ Disabled | 3 | Enable + Configure agent |
| **TaskScheduler** | ✅ Enabled | 3 | Configure agent only |
| **DNS-Server** | ✅ Enabled* | 2 | Configure agent only |
| **DNS-Server-Analytic** | ❌ Disabled | (included) | Enable + Configure agent |
| **LDAP-Client/Debug** | ❌ Disabled | (included) | Enable + Configure agent |
| **LSA** | ✅ Enabled | (included) | Configure agent only |
| **TerminalServices** | ✅ Enabled | 1 | Configure agent only |
| **SmbClient/Security** | ✅ Enabled | (included) | Configure agent only |
| **SmbClient/Connectivity** | ✅ Enabled | (included) | Configure agent only |
| **AppLocker** | ✅ Enabled* | (included) | Configure agent only |
| **Security-Mitigations** | ✅ Enabled | 2 | Configure agent only |
| **AppXDeployment** | ✅ Enabled | 7 | Configure agent only |

\* Enabled if feature is configured/installed

---

## 3. Enable Disabled Channels

### DriverFrameworks (USB Detection, Drivers)

```powershell
# Enable channel
wevtutil sl Microsoft-Windows-DriverFrameworks-UserMode/Operational /e:true

# Verify
wevtutil gl Microsoft-Windows-DriverFrameworks-UserMode/Operational | Select-String "enabled"
```

**Use case:** Detects USB device insertions, driver installations

### NTLM Authentication

```powershell
# Enable channel
wevtutil sl Microsoft-Windows-NTLM/Operational /e:true

# Verify
wevtutil gl Microsoft-Windows-NTLM/Operational | Select-String "enabled"
```

**Use case:** Detects NTLM authentication events, pass-the-hash attacks

### DNS Server Analytical (DNS Servers only)

```powershell
# Enable channel
wevtutil sl Microsoft-Windows-DNS-Server/Analytical /e:true

# Verify
wevtutil gl Microsoft-Windows-DNS-Server/Analytical | Select-String "enabled"
```

**Use case:** DNS query analysis, DNS tunneling detection

### LDAP Client Debug

```powershell
# Enable channel
wevtutil sl Microsoft-Windows-LDAP-Client/Debug /e:true

# Verify
wevtutil gl Microsoft-Windows-LDAP-Client/Debug | Select-String "enabled"
```

**Use case:** LDAP reconnaissance, Active Directory attacks

---

## 4. Wazuh Agent Configuration

### Configure ossec.conf on Windows Agents

**Location:** `C:\Program Files (x86)\ossec-agent\ossec.conf`

Add the following `<localfile>` blocks to the `<ossec_config>` section:

```xml
<ossec_config>

  <!-- Sysmon Events (REQUIRED for 3,900+ rules) -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- DriverFrameworks (USB detection, drivers) - 1 rule -->
  <localfile>
    <location>Microsoft-Windows-DriverFrameworks-UserMode/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Code Integrity (unsigned binaries, integrity violations) - 10 rules -->
  <localfile>
    <location>Microsoft-Windows-CodeIntegrity/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Windows Firewall (blocked connections, rule changes) - 8 rules -->
  <localfile>
    <location>Microsoft-Windows-Windows Firewall With Advanced Security/Firewall</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- BITS Client (malicious downloads, persistence) - 7 rules -->
  <localfile>
    <location>Microsoft-Windows-Bits-Client/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- DNS Client (DNS queries from endpoints) - 6 rules -->
  <localfile>
    <location>Microsoft-Windows-DNS Client Events/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- NTLM (authentication events, pass-the-hash) - 3 rules -->
  <localfile>
    <location>Microsoft-Windows-NTLM/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Task Scheduler (scheduled task abuse) - 3 rules -->
  <localfile>
    <location>Microsoft-Windows-TaskScheduler/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- DNS Server (for DNS servers only) - 2 rules -->
  <localfile>
    <location>DNS Server</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- DNS Server Analytical (for DNS servers only) -->
  <localfile>
    <location>Microsoft-Windows-DNS-Server/Analytical</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- LDAP Client Debug (AD reconnaissance) -->
  <localfile>
    <location>Microsoft-Windows-LDAP-Client/Debug</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- LSA Server (authentication, LSA attacks) -->
  <localfile>
    <location>Microsoft-Windows-LSA/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Terminal Services (RDP sessions) - 1 rule -->
  <localfile>
    <location>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- SMB Client Security (SMB attacks, lateral movement) -->
  <localfile>
    <location>Microsoft-Windows-SmbClient/Security</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- SMB Client Connectivity -->
  <localfile>
    <location>Microsoft-Windows-SmbClient/Connectivity</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- AppLocker (blocked executables) -->
  <localfile>
    <location>Microsoft-Windows-AppLocker/EXE and DLL</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-AppLocker/MSI and Script</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-AppLocker/Packaged app-Deployment</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-AppLocker/Packaged app-Execution</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Security Mitigations (exploit attempts, DEP/ASLR violations) - 2 rules -->
  <localfile>
    <location>Microsoft-Windows-Security-Mitigations/KernelMode</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-Security-Mitigations/UserMode</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- AppX Deployment (malicious app packages) - 7 rules -->
  <localfile>
    <location>Microsoft-Windows-AppXDeploymentServer/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

</ossec_config>
```

### Minimal Configuration (Sysmon Only)

If you only want to deploy Sysmon rules (~3,900 rules), use this minimal config:

```xml
<ossec_config>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
```

### Restart Wazuh Agent

```powershell
Restart-Service -Name wazuh
```

---

## 5. Verification

### Check Agent Configuration

```powershell
# View configured log sources
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.conf" | Select-String -Pattern "location"
```

### Check Event Flow to Wazuh

On **Wazuh Manager**:

```bash
# Monitor incoming events from Windows agent
tail -f /var/ossec/logs/archives/archives.log | grep "win.system.channel"

# Check specific channel
tail -f /var/ossec/logs/archives/archives.log | grep "Microsoft-Windows-Sysmon"
```

### Test Rule Triggering

On **Windows endpoint**, trigger a test event:

```powershell
# Trigger Sysmon process creation
notepad.exe

# Trigger DriverFrameworks (if enabled)
# Plug in a USB device

# Trigger CodeIntegrity (if monitoring enabled)
# Run an unsigned binary
```

On **Wazuh Manager**, check alerts:

```bash
tail -f /var/ossec/logs/alerts/alerts.log
```

---

## 6. Security/System/Application Support

**Current Status:**

| Channel | Rules Converted | Method |
|---------|-----------------|--------|
| Security | 183 | EventID-based parents (200100-200103) |
| System | Partial | EventID-based detection |
| Application | Partial | EventID-based detection |

**Why Sysmon is Recommended:**
- 2,000+ process creation rules (vs 0 for Event 4688)
- Richer fields (OriginalFileName, Hashes, ParentCommandLine)
- No field transformations needed
- Better detection coverage

**Note:** Security Event 4688 requires separate GPO for CommandLine logging and lacks critical detection fields.

---

## 7. Performance Considerations

### Event Volume Estimates (per endpoint)

| Channel | Volume | Impact |
|---------|--------|--------|
| Sysmon | Medium-High | Filter in config (exclude noisy events) |
| CodeIntegrity | Low | Minimal |
| Firewall | Medium | Can be high if many blocked connections |
| BITS-Client | Very Low | Minimal |
| DNS-Client | High | Consider filtering benign domains |
| NTLM | Low-Medium | Depends on environment |
| TaskScheduler | Low | Minimal |
| Others | Very Low | Minimal |

### Sysmon Config Optimization

Use a curated Sysmon config to reduce noise:

- **SwiftOnSecurity config:** Good starting point
- **ION-Storm config:** More comprehensive
- **Olaf Hartong config:** Modular approach

**Filter out:**
- System processes (svchost.exe, explorer.exe)
- Known-good software (Microsoft, Adobe)
- Network connections to CDNs

### Wazuh Agent Buffering

On high-volume endpoints, increase agent buffer:

```xml
<client_buffer>
  <disabled>no</disabled>
  <queue_size>50000</queue_size>
  <events_per_second>5000</events_per_second>
</client_buffer>
```

---

## 8. Quick Reference

### Enable All Disabled Channels (PowerShell)

```powershell
# Run as Administrator
$channels = @(
    "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
    "Microsoft-Windows-NTLM/Operational",
    "Microsoft-Windows-DNS-Server/Analytical",
    "Microsoft-Windows-LDAP-Client/Debug"
)

foreach ($channel in $channels) {
    Write-Host "Enabling $channel..."
    wevtutil sl $channel /e:true
}

Write-Host "All channels enabled. Verify with: wevtutil gl <channel> | Select-String enabled"
```

### Deploy Agent Config via Group Policy

1. Create `ossec.conf` with all `<localfile>` entries
2. Deploy via GPO to `C:\Program Files (x86)\ossec-agent\`
3. Restart agents: `Restart-Service wazuh`

---

## 9. Troubleshooting

### Agent Not Sending Events

```powershell
# Check agent status
Get-Service wazuh

# Check agent log
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 50

# Verify channel exists
wevtutil enum-logs | Select-String "Sysmon"
```

### Rules Not Triggering

On **Wazuh Manager**:

```bash
# Test event with wazuh-logtest
/var/ossec/bin/wazuh-logtest

# Check rule compilation errors
grep -i "error\|warning" /var/ossec/logs/ossec.log | grep -i sigma

# Verify parent rules loaded (should show 30 rules from IDs 109970-109999)
grep -r "id=\"109" /var/ossec/etc/rules/100001-windows_builtin_channels_parent.xml | wc -l
```

### High CPU/Memory on Agent

- Reduce Sysmon verbosity (exclude noisy events)
- Increase agent buffer queue size
- Disable low-value channels (diagnosis-scripted, shell-core)

---

## 10. Summary Checklist

**On Windows Endpoints:**
- [ ] Install Sysmon with config
- [ ] Enable disabled channels (DriverFrameworks, NTLM, DNS-Server-Analytic, LDAP-Client/Debug)
- [ ] Configure `ossec.conf` with all `<localfile>` entries
- [ ] Restart Wazuh agent
- [ ] Verify event flow to manager

**On Wazuh Manager:**
- [ ] Deploy parent rule file (100001-windows_builtin_channels_parent.xml)
- [ ] Deploy Sigma rule files (200400-*)
- [ ] Update `ossec.conf` ruleset includes
- [ ] Restart Wazuh manager
- [ ] Test with wazuh-logtest
- [ ] Monitor alerts

---

**For questions or issues, see main [README.md](README.md)**
