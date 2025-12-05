# StoW - Sigma to Wazuh Converter

Convert [Sigma](https://github.com/SigmaHQ/sigma) detection rules into [Wazuh](https://wazuh.com) SIEM rules automatically.

## Overview

StoW is a powerful converter that transforms Sigma detection rules (a generic signature format for SIEM systems) into Wazuh-compatible XML rules. It intelligently handles complex detection logic, field mappings, and automatically manages rule IDs across different products (Windows, Linux, Azure, M365).

### Key Features

- ✅ **Automatic Field Mapping** - Maps Sigma fields to Wazuh event data fields for multiple products
- ✅ **Product-Specific Rule IDs** - Segregates rules by product with non-overlapping ID ranges
- ✅ **Intelligent File Splitting** - Splits large rule sets into multiple files for optimal performance
- ✅ **CDB List Generation** - Automatically converts oversized fields to CDB lists
- ✅ **MITRE ATT&CK Integration** - Preserves MITRE technique tags from Sigma rules
- ✅ **Comprehensive Validation** - Validates configuration and provides clear error messages
- ✅ **Flexible Filtering** - Convert only rules matching specific products, services, or categories

## Requirements

- **Go** 1.18 or higher
- **Sigma Rules** repository (clone from [SigmaHQ](https://github.com/SigmaHQ/sigma))
- **Wazuh** 3.11.0+ (for deployment)

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/StoW.git
cd StoW
```

### 2. Clone Sigma Rules

```bash
cd ..
git clone https://github.com/SigmaHQ/sigma.git
cd StoW
```

### 3. Build the Converter

```bash
go build -o stow stow.go
```

## Configuration

Edit `config.yaml` to customize the conversion process:

### Basic Configuration

```yaml
Title: Sigma to Wazuh Converter Config
Info: false   # Set to true for verbose output
Debug: false  # Set to true for debug logging

Sigma:
  # URL base for rule references
  BaseUrl: https://github.com/SigmaHQ/sigma/tree/master/rules

  # Path to Sigma rules directory
  RulesRoot: ../sigma/rules

  # Rule status to convert
  RuleStatus:
    - stable
    - test
    # - experimental  # Uncomment to include experimental rules
```

### Product Selection

```yaml
Sigma:
  # Convert only these products (comment out to convert all)
  ConvertProducts:
    - windows
    - linux
    - azure
    - m365
```

### Wazuh Rule ID Configuration

```yaml
Wazuh:
  # Starting rule ID
  RuleIdStart: 200000

  # Product-specific ID ranges (10,000 IDs per product)
  ProductRuleIdStart:
    windows: 200000  # Windows rules: 200000-209999
    linux: 210000    # Linux rules:   210000-219999
    azure: 220000    # Azure rules:   220000-229999
    m365: 230000     # M365 rules:    230000-239999

  # Maximum rules per file (0 = no splitting)
  MaxRulesPerFile: 500
```

### Alert Configuration

```yaml
Wazuh:
  Levels:
    informational: 5
    low: 7
    medium: 10
    high: 12
    critical: 15

  Options:
    NoFullLog: true      # Don't include full log in alerts
    EmailAlert: true     # Enable email alerts
    EmailLevels:
      - critical
      - high
```

## Usage

### Basic Conversion

```bash
./stow
```

### With Verbose Output

```bash
./stow --info
```

### With Debug Information

```bash
./stow --debug
```

### Example Output

```
Product windows: 1523 Wazuh rules
Product linux: 234 Wazuh rules
Product azure: 187 Wazuh rules
Product m365: 145 Wazuh rules

Splitting windows: 1523 rules into 4 files (500 rules per file)
  Created 200000-sigma_windows_part1.xml with 500 rules
  Created 200000-sigma_windows_part2.xml with 500 rules
  Created 200000-sigma_windows_part3.xml with 500 rules
  Created 200000-sigma_windows_part4.xml with 23 rules
Created 210000-sigma_linux.xml with 234 rules
Created 220000-sigma_azure.xml with 187 rules
Created 230000-sigma_m365.xml with 145 rules

***************************************************************************
 Number of Sigma Experimental rules skipped: 234
    Number of Sigma TIMEFRAME rules skipped: 45
       Number of Sigma CONFIG rules skipped: 12
Number of Sigma rules CONVERTED TO CDB: 23
---------------------------------------------------------------------------
                Total Sigma rules converted: 1523
---------------------------------------------------------------------------
                  Total Wazuh rules created: 2089
---------------------------------------------------------------------------
                          Total Sigma rules: 2345
                    Sigma rules converted %: 64.93
***************************************************************************
```

## Output Files

### XML Rule Files

- `{ID}-sigma_{product}.xml` - Single file for product
- `{ID}-sigma_{product}_part{N}.xml` - Split files (if MaxRulesPerFile is set)

Example:
```
200000-sigma_windows_part1.xml
200000-sigma_windows_part2.xml
210000-sigma_linux.xml
220000-sigma_azure.xml
```

### CDB List Files

If rules contain large field values, they're automatically converted to CDB lists:

```
lists/sigma_abc123_0_win_eventdata_commandLine
lists/sigma_def456_1_win_eventdata_image
```

### Configuration Files

- `rule_ids.json` - Tracks Sigma ID to Wazuh ID mappings (preserves IDs between runs)
- `WAZUH_CDB_CONFIG.txt` - Configuration snippet for ossec.conf
- `deploy_cdb_lists.sh` - Deployment script for CDB lists

## Deploying to Wazuh

### Option 1: Automated Deployment (Local)

```bash
sudo ./deploy_cdb_lists.sh localhost
```

### Option 2: Automated Deployment (Remote)

```bash
./deploy_cdb_lists.sh <wazuh-server-ip> <ssh-user>
```

### Option 3: Manual Deployment

1. **Copy XML rule files to Wazuh**

```bash
sudo cp *-sigma_*.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/rules/sigma_*.xml
sudo chmod 640 /var/ossec/etc/rules/sigma_*.xml
```

2. **Copy CDB list files (if generated)**

```bash
sudo cp lists/* /var/ossec/etc/lists/
sudo chown wazuh:wazuh /var/ossec/etc/lists/sigma_*
sudo chmod 640 /var/ossec/etc/lists/sigma_*
```

3. **Update Wazuh Configuration**

Edit `/var/ossec/etc/ossec.conf` and add to the `<ruleset>` section:

```xml
<ruleset>
  <!-- Existing rules -->

  <!-- Sigma Rules -->
  <include>200000-sigma_windows_part1.xml</include>
  <include>200000-sigma_windows_part2.xml</include>
  <include>210000-sigma_linux.xml</include>
  <include>220000-sigma_azure.xml</include>
  <include>230000-sigma_m365.xml</include>

  <!-- CDB Lists (if applicable) -->
  <list>etc/lists/sigma_abc123_0_win_eventdata_commandLine</list>
  <list>etc/lists/sigma_def456_1_win_eventdata_image</list>
</ruleset>
```

4. **Restart Wazuh Manager**

```bash
sudo systemctl restart wazuh-manager
```

5. **Verify Rules Loaded**

```bash
sudo /var/ossec/bin/wazuh-logtest
# Test with sample events
```

## Field Mappings

StoW includes comprehensive field mappings for multiple products:

### Windows Event Fields
- Sysmon events (Process, Network, Registry, etc.)
- Windows Security events
- PowerShell logs
- Windows Defender logs

### Linux Audit Fields
- Auditd events
- Process execution
- File system operations

### Cloud Platforms
- **Azure**: Activity logs, sign-ins, operations
- **M365**: Office 365 audit logs, operations

### Network
- **Zeek**: Connection logs, DNS, HTTP

See `config.yaml` for complete field mapping definitions.

## Advanced Usage

### Converting Specific Categories

```yaml
Sigma:
  ConvertCategories:
    - process_creation
    - network_connection
```

### Converting Specific Services

```yaml
Sigma:
  ConvertServices:
    - sysmon
    - security
```

### Skipping Specific Rules

```yaml
Sigma:
  SkipIds:
    - 12345678-1234-1234-1234-123456789abc
    - 87654321-4321-4321-4321-cba987654321
```

### Custom Field Mappings

Add custom mappings in `config.yaml`:

```yaml
Wazuh:
  FieldMaps:
    MyProduct:
      CustomField: myproduct.data.customfield
      AnotherField: myproduct.data.anotherfield
```

## Troubleshooting

### Issue: "Sigma RulesRoot path does not exist"

**Solution**: Ensure the Sigma repository is cloned and the path in `config.yaml` is correct:

```bash
cd ..
git clone https://github.com/SigmaHQ/sigma.git
cd StoW
# Update config.yaml RulesRoot to: ../sigma/rules
```

### Issue: "Product rule ID range overlaps"

**Solution**: Ensure product ID ranges don't overlap. Each product should have a unique range (recommended: 10,000 IDs per product).

### Issue: Rules not triggering in Wazuh

**Checklist**:
1. Verify rules are loaded: Check `/var/ossec/logs/ossec.log` for errors
2. Verify field mappings match your log format
3. Test with sample events using `wazuh-logtest`
4. Check rule dependencies (`if_sid` values)

### Issue: CDB lists not working

**Solution**:
1. Ensure CDB lists are declared in `ossec.conf`
2. Restart Wazuh after adding lists (Wazuh 3.11.0+ compiles them automatically)
3. Check permissions: `chown wazuh:wazuh /var/ossec/etc/lists/sigma_*`

## Performance Considerations

- **Large Rule Sets**: Use `MaxRulesPerFile` to split into multiple files (recommended: 500-1000 rules per file)
- **CDB Lists**: Large field values are automatically converted to CDB lists for O(1) lookup performance
- **Rule Dependencies**: Minimize `if_sid` chains for better performance

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with clear commit messages
4. Add tests for new functionality
5. Submit a pull request

### Development

```bash
# Run tests
go test ./...

# Build
go build -o stow stow.go

# Run with debug
./stow --debug
```

## Project Structure

```
StoW/
├── stow.go              # Main converter logic
├── config.yaml          # Configuration file
├── get-wazuh_rule_info.py  # Utility for analyzing Wazuh rules
├── README.md            # This file
├── LICENSE              # License file
├── go.mod               # Go module definition
└── go.sum               # Go dependencies
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- **Sigma Project**: [SigmaHQ](https://github.com/SigmaHQ/sigma) - Generic signature format for SIEM systems
- **Wazuh**: [Wazuh](https://wazuh.com) - Open source security platform
- **Detection Rule License**: Sigma rules are licensed under [DRL](https://github.com/SigmaHQ/Detection-Rule-License)

## Resources

- [Sigma Documentation](https://sigmahq.io/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Wazuh Rule Reference](https://documentation.wazuh.com/current/user-manual/ruleset/index.html)
- [MITRE ATT&CK](https://attack.mitre.org/)

## Support

For issues, questions, or contributions:
- **Issues**: [GitHub Issues](https://github.com/yourusername/StoW/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/StoW/discussions)

---

**Note**: Always test converted rules in a non-production environment before deploying to production Wazuh instances.
