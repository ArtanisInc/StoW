# StoW - Sigma to Wazuh Converter

**High-performance converter transforming [Sigma](https://github.com/SigmaHQ/sigma) detection rules into [Wazuh](https://wazuh.com) SIEM rules with intelligent optimization.**

[![Conversion Rate](https://img.shields.io/badge/conversion-84.04%25-success)]()
[![Rules Generated](https://img.shields.io/badge/rules-4345-blue)]()
[![Go Version](https://img.shields.io/badge/go-1.18+-00ADD8)]()

---

## 🎯 Overview

StoW automatically converts Sigma detection rules into production-ready Wazuh XML rules with:
- **Smart parent rule chaining** for 92.2% of Linux rules (auditd optimization)
- **Event ID-based optimization** for Windows rules
- **Automatic CDB list generation** for large field sets (10,930 entries)
- **Multi-product support** (Windows, Linux, Azure, M365)

### Current Statistics

```
Products:    4 (Windows, Linux, Azure, M365)
Total Rules: 4,345 Wazuh rules from 2,585 Sigma rules
Conversion:  84.04% (495 skipped: experimental/unsupported)
File Size:   87,933 lines across 11 XML files
CDB Lists:   15 files with 10,930 optimized entries
```

### Windows Event Sources

StoW is **primarily Sysmon-focused** but also supports select Windows built-in event channels:

| Source | Rules | Setup Required |
|--------|-------|----------------|
| **Sysmon** | ~3,900 | Install Sysmon (see [WINDOWS_SETUP.md](WINDOWS_SETUP.md)) |
| **Built-in Channels** | ~50 | Enable channels + Configure Wazuh agent |
| **Security/System/App** | ❌ Not supported | Requires per-service field mappings (StoW architecture limitation) |

**Supported built-in channels:** DriverFrameworks, CodeIntegrity, Firewall, BITS-Client, DNS-Client, NTLM, TaskScheduler, AppXDeployment, and more.

**📖 See [WINDOWS_SETUP.md](WINDOWS_SETUP.md) for complete Windows setup guide** (channel activation, Wazuh agent configuration).

---

## ⚡ Key Features

### Intelligence & Optimization
- ✅ **Linux if_sid Optimization** - Converts field matching to parent rule chaining (92.2% coverage)
- ✅ **Windows Event ID Parents** - Auto-generates parent rules (200100-200103)
- ✅ **PowerShell Category Parents** - Dedicated parent rules (200000-200003)
- ✅ **Sysmon Extended Events** - Support for Events 6, 17-22, 25 via 100000-sysmon_new_events.xml
- ✅ **Built-in Channel Parents** - 11 parent rules for Windows channels (100001-100011, IDs 109983-109999)

### Performance & Scalability
- ✅ **Intelligent File Splitting** - Splits into 500-rule chunks for optimal Wazuh performance
- ✅ **Automatic CDB Lists** - Converts 1000+ value fields to O(1) lookup lists
- ✅ **Product-Specific ID Ranges** - Non-overlapping IDs (200000+)

### Compliance & Integration
- ✅ **MITRE ATT&CK Tags** - Preserves technique mappings from Sigma
- ✅ **Comprehensive Metadata** - Author, dates, status, references
- ✅ **Email Alerts** - Configurable for critical/high severity
- ✅ **No Full Log** - Optimized alert payloads

---

## 📦 Requirements

| Component | Version | Purpose |
|-----------|---------|---------|
| **Go** | 1.18+ | Build StoW converter |
| **Sigma Rules** | Latest | Source detection rules |
| **Wazuh** | 3.11.0+ | Target SIEM platform |
| **Auditd** (Linux) | Any | Linux log source |

---

## 🚀 Quick Start

### 1. Setup

```bash
# Clone StoW
git clone https://github.com/ArtanisInc/StoW.git
cd StoW

# Clone Sigma rules (sibling directory)
cd ..
git clone https://github.com/SigmaHQ/sigma.git
cd StoW

# Build converter
go build -o stow stow.go
```

### 2. Configure

Edit `config.yaml` - key settings:

```yaml
Sigma:
  RulesRoot: ../sigma/rules
  RuleStatus: [stable, test]  # Skip experimental
  ConvertProducts: [windows, linux, azure, m365]

Wazuh:
  MaxRulesPerFile: 500
  EmailAlert: false  # Disable email alerts

  ProductRuleIdStart:
    windows: 200400  # Reserve 200000-200399 for parents
    linux: 210007    # Reserve 210000-210006 for parents
```

### 3. Convert

```bash
./stow -c config.yaml

# Output:
# Created 200400-sigma_windows_part1.xml (500 rules)
# Created 200400-sigma_windows_part2.xml (500 rules)
# ...
# Total: 4,345 Wazuh rules (84.04% conversion)
```

---

## 📁 Output Files

### XML Rule Files
```
200400-sigma_windows_part[1-8].xml  # 3,905 Windows rules
210007-sigma_linux.xml              # 289 Linux rules
220000-sigma_azure.xml              # 134 Azure rules
230000-sigma_m365.xml               # 17 M365 rules
```

### Parent Rule Files

```
# Sysmon Extended Events
100000-sysmon_new_events.xml  # Sysmon Events 6, 17-22, 25

# Windows Built-in Channel Parents (100001-100011, ~50 rules)
100001-driverframeworks_parent.xml       # USB detection, drivers (ID 109999)
100002-codeintegrity_parent.xml          # Code integrity violations (ID 109998)
100003-firewall_parent.xml               # Firewall events (ID 109997)
100004-bitsclient_parent.xml             # BITS transfers (ID 109996)
100005-dnsclient_parent.xml              # DNS queries (ID 109995)
100006-ntlm_parent.xml                   # NTLM authentication (ID 109994)
100007-taskscheduler_parent.xml          # Scheduled tasks (ID 109993)
100008-dnsserver_parent.xml              # DNS Server (ID 109992)
100009-dnsserver_analytic_parent.xml     # DNS Server Analytical (ID 109991)
100010-other_builtin_parent.xml          # LDAP, LSA, TerminalServices, SMB, AppLocker, Mitigations (IDs 109984-109990)
100011-appxdeployment_parent.xml         # AppX package deployment (ID 109983)

# Embedded in Windows rule files
200000-* (in Windows files)   # PowerShell parents (4 rules)
200100-* (in Windows files)   # Event ID parents (4 rules)

# Embedded in Linux rule file
210000-* (in Linux file)      # Auditd parents (7 rules)
```

### CDB Lists (15 files, 10,930 entries)
```
lists/sigma_*_commandLine       # Command line patterns
lists/sigma_*_hashes            # File hashes
lists/sigma_*_imageLoaded       # DLL names
deploy_cdb_lists.sh             # Deployment script
WAZUH_CDB_CONFIG.txt            # ossec.conf snippet
```

### Tracking Files
```
rule_ids.json  # Sigma→Wazuh ID mappings (persistent)
```

---

## 🔧 Deployment

### Automated (Recommended)

```bash
# Local deployment
sudo ./deploy_cdb_lists.sh localhost

# Remote deployment
./deploy_cdb_lists.sh <wazuh-server> <ssh-user>
```

### Manual Steps

<details>
<summary>Click to expand manual deployment steps</summary>

#### 1. Copy Rules
```bash
# Copy parent rules (Sysmon + Built-in channels)
sudo cp 100000-sysmon_new_events.xml /var/ossec/etc/rules/
sudo cp 1000[01][01]-*.xml /var/ossec/etc/rules/  # Built-in channel parents (100001-100011)

# Copy Sigma rules
sudo cp 200400-sigma_windows_part*.xml /var/ossec/etc/rules/
sudo cp 210007-sigma_linux.xml /var/ossec/etc/rules/
sudo cp 220000-sigma_azure.xml /var/ossec/etc/rules/
sudo cp 230000-sigma_m365.xml /var/ossec/etc/rules/

# Set permissions
sudo chown wazuh:wazuh /var/ossec/etc/rules/*sigma*.xml /var/ossec/etc/rules/1000*.xml
sudo chmod 640 /var/ossec/etc/rules/*sigma*.xml /var/ossec/etc/rules/1000*.xml
```

#### 2. Copy CDB Lists
```bash
sudo cp lists/* /var/ossec/etc/lists/
sudo chown wazuh:wazuh /var/ossec/etc/lists/sigma_*
sudo chmod 640 /var/ossec/etc/lists/sigma_*
```

#### 3. Update ossec.conf (Wazuh Manager)
```xml
<ruleset>
  <!-- Parent Rules -->
  <include>100000-sysmon_new_events.xml</include>
  <include>100001-driverframeworks_parent.xml</include>
  <include>100002-codeintegrity_parent.xml</include>
  <include>100003-firewall_parent.xml</include>
  <include>100004-bitsclient_parent.xml</include>
  <include>100005-dnsclient_parent.xml</include>
  <include>100006-ntlm_parent.xml</include>
  <include>100007-taskscheduler_parent.xml</include>
  <include>100008-dnsserver_parent.xml</include>
  <include>100009-dnsserver_analytic_parent.xml</include>
  <include>100010-other_builtin_parent.xml</include>
  <include>100011-appxdeployment_parent.xml</include>

  <!-- Sigma Rules -->
  <include>200400-sigma_windows_part1.xml</include>
  <include>200400-sigma_windows_part2.xml</include>
  <include>200400-sigma_windows_part3.xml</include>
  <include>200400-sigma_windows_part4.xml</include>
  <include>200400-sigma_windows_part5.xml</include>
  <include>200400-sigma_windows_part6.xml</include>
  <include>200400-sigma_windows_part7.xml</include>
  <include>200400-sigma_windows_part8.xml</include>
  <include>210007-sigma_linux.xml</include>
  <include>220000-sigma_azure.xml</include>
  <include>230000-sigma_m365.xml</include>
</ruleset>

<!-- CDB Lists - see WAZUH_CDB_CONFIG.txt for full list -->
```

**Note:** See [WINDOWS_SETUP.md](WINDOWS_SETUP.md) for **Wazuh agent configuration** (required to collect built-in channels).

#### 4. Install Linux Decoders (Required for Linux rules)
```bash
sudo cp wazuh-decoders/auditd_decoders.xml /var/ossec/etc/decoders/
sudo chown wazuh:wazuh /var/ossec/etc/decoders/auditd_decoders.xml
sudo chmod 640 /var/ossec/etc/decoders/auditd_decoders.xml
```

#### 5. Restart & Verify
```bash
sudo systemctl restart wazuh-manager
sudo /var/ossec/bin/wazuh-logtest  # Test with sample events
```

</details>

---

## 📊 Rule ID Allocation

| Product | ID Range | Count | Reserved IDs | Purpose |
|---------|----------|-------|--------------|---------|
| PowerShell Parents | 200000-200003 | 4 | - | ps_script, ps_module, ps_classic |
| Event ID Parents | 200100-200103 | 4 | - | EventID-based grouping |
| **Windows Rules** | 200400-209999 | 3,905 | 200000-200399 | Sigma Windows detections |
| Auditd Parents | 210000-210006 | 7 | - | SYSCALL, EXECVE, PATH, etc. |
| **Linux Rules** | 210007-219999 | 289 | 210000-210006 | Sigma Linux detections |
| **Azure Rules** | 220000-229999 | 134 | - | Sigma Azure detections |
| **M365 Rules** | 230000-239999 | 17 | - | Sigma M365 detections |

---

## 🔬 Advanced Configuration

### Skip Specific Events (Example: Sysmon Events 16, 27-29)
```yaml
Sigma:
  SkipIds:
    - 8ac03a65-6c84-4116-acad-dc1558ff7a77  # Event 16
    - 23b71bc5-953e-4971-be4c-c896cda73fc2  # Event 27
    - c3e5c1b1-45e9-4632-b242-27939c170239  # Event 28
    - 693a44e9-7f26-4cb6-b787-214867672d3a  # Event 29
```

### Custom Field Mappings
See `config.yaml` FieldMaps section for:
- Windows (100+ fields)
- Linux (28 fields - complete)
- Azure, M365, Zeek

### Filter by Category/Service
```yaml
Sigma:
  ConvertCategories: [process_creation, network_connection]
  ConvertServices: [sysmon, security]
```

---

## 🐛 Troubleshooting

### Rules Not Triggering

**Check decoder installation (Linux only):**
```bash
ls -l /var/ossec/etc/decoders/auditd_decoders.xml
# If missing: cp wazuh-decoders/auditd_decoders.xml /var/ossec/etc/decoders/
```

**Verify rules loaded:**
```bash
grep -i "error\|warning" /var/ossec/logs/ossec.log
```

**Test with wazuh-logtest:**
```bash
/var/ossec/bin/wazuh-logtest -v < sample_event.log
```

### CDB Lists Not Working

**Verify configuration:**
```bash
grep "sigma_" /var/ossec/etc/ossec.conf
```

**Check compilation (Wazuh 3.11.0+):**
```bash
ls -l /var/ossec/etc/lists/sigma_*.cdb
# CDB files auto-compiled on Wazuh restart
```

### High Memory Usage

**Reduce rules per file:**
```yaml
Wazuh:
  MaxRulesPerFile: 300  # Lower from 500
```

---

## 📚 Documentation

- **Main README**: This file
- **Windows Setup Guide**: [WINDOWS_SETUP.md](WINDOWS_SETUP.md) - Sysmon installation, channel activation, Wazuh agent config
- **Auditd Decoders**: [wazuh-decoders/README.md](wazuh-decoders/README.md) - Linux audit decoder documentation
- **Sigma Docs**: https://sigmahq.io/
- **Wazuh Docs**: https://documentation.wazuh.com/

---

## 🤝 Contributing

1. Fork repository
2. Create feature branch
3. Make changes with tests
4. Submit PR with clear description

---

## 📜 License

MIT License - see LICENSE file

---

## 🙏 Acknowledgments

- **Sigma Project** - [SigmaHQ](https://github.com/SigmaHQ/sigma)
- **Wazuh** - [Wazuh.com](https://wazuh.com)
- **Detection Rule License** - [DRL](https://github.com/SigmaHQ/Detection-Rule-License)

---

**⚠️ Production Warning**: Always test in non-production environment first. Verify field mappings match your log sources.
