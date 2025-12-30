# Wazuh Auditd Decoders for StoW Linux Rules

This directory contains essential Wazuh decoder files required for Linux/auditd rule detection.

## 🎯 Purpose

The StoW converter generates Linux rules with parent rule chaining (`<if_sid>` tags) that reference specific auditd decoders. **Without these decoders installed, the Linux rules will not function.**

## 📦 Files

### `auditd_decoders.xml`
Complete Wazuh decoder definitions for parsing auditd logs and extracting structured fields.

**Supported Decoders (7 total):**
- `auditd-syscall` → Parent rule 210000 (12 rules)
- `auditd-execve` → Parent rule 210001 (217 rules)
- `auditd-path` → Parent rule 210002 (20 rules)
- `auditd-config_change` → Parent rule 210003 (0 rules)
- `auditd-user_and_cred` → Parent rule 210004 (1 rule)
- `auditd-service_stop` → Parent rule 210005 (1 rule) **[NEW]**
- `auditd-tty` → Parent rule 210006 (1 rule) **[NEW]**

### `auditd.conf`
Reference auditd configuration optimized for security monitoring with Wazuh integration.

**Key Features:**
- Monitors system calls, user management, privilege escalation
- Detects suspicious tools (curl, wget, netcat, SSH, nmap)
- Tracks file deletions, permission changes, network connections
- Excludes Wazuh agent activity to reduce noise
- Monitors package installations (rpm, apt, pip, npm)

## 🔧 Installation Instructions

### Step 1: Install Auditd Decoders

```bash
# On Wazuh Manager
sudo cp auditd_decoders.xml /var/ossec/etc/decoders/
sudo chown wazuh:wazuh /var/ossec/etc/decoders/auditd_decoders.xml
sudo chmod 640 /var/ossec/etc/decoders/auditd_decoders.xml
```

### Step 2: Install StoW Linux Rules

```bash
# Copy generated Linux rules
sudo cp 210000-sigma_linux.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/rules/210000-sigma_linux.xml
sudo chmod 640 /var/ossec/etc/rules/210000-sigma_linux.xml
```

### Step 3: Configure Auditd on Linux Agents (Optional)

If you want to use the provided auditd configuration:

```bash
# On Linux agents being monitored
sudo cp auditd.conf /etc/audit/rules.d/auditd.rules
sudo chmod 640 /etc/audit/rules.d/auditd.rules
sudo augenrules --load
sudo systemctl restart auditd
```

**⚠️ Important:** Review `auditd.conf` before deploying - it's comprehensive and may generate high log volumes.

### Step 4: Restart Wazuh Manager

```bash
sudo systemctl restart wazuh-manager
```

## 🧪 Testing

### Test Decoders with wazuh-logtest

```bash
# Test SERVICE_STOP decoder (parent rule 210005)
echo 'type=SERVICE_STOP msg=audit(1722957155.494:4802): pid=1 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='\''unit=firewalld comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'\''UID="root" AUID="unset"' | /var/ossec/bin/wazuh-logtest -v

# Expected output should show:
# - decoder: auditd-service_stop
# - rule: 210005 (parent) and 210026 (Disable System Firewall)
# - extracted field: audit.unit=firewalld
```

```bash
# Test TTY decoder (parent rule 210006)
echo 'type=USER_TTY msg=audit(1573643958.798:1973): pid=2964 uid=0 auid=1000 ses=22 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 data=636174202F7661722F6C6F672F61756469742F61756469742E6C6F67UID="root" AUID="testuser"' | /var/ossec/bin/wazuh-logtest -v

# Expected output should show:
# - decoder: auditd-tty
# - rule: 210006 (parent) and 210034/210036 (Linux Keylogging)
# - extracted field: audit.data=(hex encoded)
```

### Verify Rule Activation

Check Wazuh manager logs for rule triggers:

```bash
# Monitor alerts in real-time
tail -f /var/ossec/logs/alerts/alerts.json

# Search for Linux Sigma rules (ID 210xxx)
grep '"rule":{"id":"210' /var/ossec/logs/alerts/alerts.json | jq .
```

## 📊 Decoder Coverage

| Parent Rule | Decoder Name | Audit Type | Child Rules | Status |
|-------------|--------------|------------|-------------|---------|
| 210000 | auditd-syscall | SYSCALL | 12 | ✅ Active |
| 210001 | auditd-execve | EXECVE | 217 | ✅ Active |
| 210002 | auditd-path | PATH | 20 | ✅ Active |
| 210003 | auditd-config_change | CONFIG_CHANGE | 0 | ⚪ Unused |
| 210004 | auditd-user_and_cred | USER_* | 1 | ✅ Active |
| 210005 | auditd-service_stop | SERVICE_STOP | 1 | ✅ Active |
| 210006 | auditd-tty | TTY/USER_TTY | 1 | ✅ Active |

**Total Coverage:** 252/282 Linux rules use parent rule chaining (89%)

## 🔍 Field Extraction

### auditd-service_stop (NEW)
Extracts fields from `type=SERVICE_STOP` events:
- `audit.id` - Audit event ID (timestamp:sequence)
- `audit.pid` - Process ID (typically 1 for systemd)
- `audit.uid` - User ID
- `audit.auid` - Audit user ID
- `audit.session` - Session ID
- `audit.subj` - SELinux security context
- `audit.unit` - **Service/unit name** (used in rule 210026 for firewall detection)
- `audit.comm` - Command name
- `audit.exe` - Executable path
- `audit.res` - Result (success/failed)

**Use Case:** Rule 210026 "Disable System Firewall" checks if `audit.unit` matches firewalld/iptables/ufw.

### auditd-tty (NEW)
Extracts fields from `type=TTY` and `type=USER_TTY` events:
- `audit.id` - Audit event ID
- `audit.pid` - Process ID
- `audit.uid` - User ID
- `audit.auid` - Audit user ID
- `audit.session` - Session ID
- `audit.subj` - SELinux security context
- `audit.data` - **Hex-encoded keystrokes** (captured terminal activity)

**Use Case:** Rules 210034/210036 detect PAM-based keylogging configurations.

## 🚨 Critical Notes

1. **Decoder-Rule Dependency:** Parent rules with `<decoded_as>` tags MUST have matching decoders installed. Missing decoders = non-functional rules.

2. **Auditd Log Format:** Decoders expect standard auditd log format from `/var/log/audit/audit.log`. Custom formats may require decoder adjustments.

3. **Performance Impact:** The provided `auditd.conf` monitors extensive system activity. Test in non-production first to assess log volume and performance impact.

4. **Storage Requirements:** Auditd logs can grow large (multi-GB daily in high-activity environments). Ensure adequate storage and log rotation.

## 📚 References

- **Original Decoders:** [ArtanisInc/Wazuh-Rules/Auditd](https://github.com/ArtanisInc/Wazuh-Rules/tree/main/Auditd)
- **Auditd Documentation:** [auditd man page](https://linux.die.net/man/8/auditd)
- **Wazuh Decoder Syntax:** [Wazuh Decoder Documentation](https://documentation.wazuh.com/current/user-manual/ruleset/custom.html#decoders)
- **StoW Converter:** [stow.go](../stow.go)

## 🔄 Maintenance

When updating StoW with new Linux parent rules:
1. Identify the required `<decoded_as>` decoder names
2. Create corresponding decoders in `auditd_decoders.xml`
3. Test with `wazuh-logtest` before production deployment
4. Update this README with new decoder coverage

## ❓ Troubleshooting

**Rules not triggering:**
```bash
# Check decoder is recognized
/var/ossec/bin/wazuh-logtest -v < sample_log.txt

# Verify rule syntax
/var/ossec/bin/wazuh-logtest -t < /var/ossec/etc/rules/210000-sigma_linux.xml
```

**Decoder not loading:**
```bash
# Check Wazuh manager logs
tail -100 /var/ossec/logs/ossec.log | grep -i "decoder\|error"

# Verify file permissions
ls -l /var/ossec/etc/decoders/auditd_decoders.xml
```

**High log volume:**
```bash
# Monitor auditd log growth
watch -n 5 'du -sh /var/log/audit/audit.log'

# Review auditd rules generating most events
aureport -i --summary
```
