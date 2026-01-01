package generator

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"

	"github.com/theflakes/StoW/pkg/types"
	"github.com/theflakes/StoW/pkg/utils"
)

// WriteWazuhXmlRules writes all generated Wazuh rules to XML files
func WriteWazuhXmlRules(c *types.Config) {
	utils.LogIt(utils.DEBUG, "", nil, c.Info, c.Debug)

	// Iterate through each product and write separate XML files
	for product, xmlRules := range c.Wazuh.XmlRules {
		if len(xmlRules.Rules) == 0 {
			continue // Skip empty rule sets
		}

		// Prepend Linux parent rules if this is a Linux product
		if product == "linux" {
			parentRules := GenerateLinuxParentRules()
			// Prepend parent rules to the beginning
			xmlRules.Rules = append(parentRules, xmlRules.Rules...)
			utils.LogIt(utils.INFO, fmt.Sprintf("Added %d Linux parent rules to %s", len(parentRules), product), nil, c.Info, c.Debug)
		}

		// Prepend PowerShell parent rules if this is a Windows product
		if product == "windows" {
			parentRules := GeneratePowerShellParentRules()
			// Prepend parent rules to the beginning
			xmlRules.Rules = append(parentRules, xmlRules.Rules...)
			utils.LogIt(utils.INFO, fmt.Sprintf("Added %d PowerShell parent rules to %s", len(parentRules), product), nil, c.Info, c.Debug)
		}

		// Prepend Windows Event ID parent rules if this is a Windows product
		if product == "windows" {
			eventParentRules := GenerateWindowsEventParentRules()
			// Prepend event parent rules after PowerShell parent rules
			xmlRules.Rules = append(eventParentRules, xmlRules.Rules...)
			utils.LogIt(utils.INFO, fmt.Sprintf("Added %d Windows Event ID parent rules to %s", len(eventParentRules), product), nil, c.Info, c.Debug)
		}

		// Get the starting ID for this product, fallback to default RuleIdStart if not configured
		startId, ok := c.Wazuh.ProductRuleIdStart[product]
		if !ok {
			startId = c.Wazuh.RuleIdStart
		}

		totalRules := len(xmlRules.Rules)
		maxRulesPerFile := c.Wazuh.MaxRulesPerFile

		// Check if we need to split the file
		if maxRulesPerFile > 0 && totalRules > maxRulesPerFile {
			// Calculate number of parts needed
			numParts := (totalRules + maxRulesPerFile - 1) / maxRulesPerFile

			fmt.Printf("Splitting %s: %d rules into %d files (%d rules per file)\n",
				product, totalRules, numParts, maxRulesPerFile)

			// Split rules into multiple files
			for part := 0; part < numParts; part++ {
				startIdx := part * maxRulesPerFile
				endIdx := startIdx + maxRulesPerFile
				if endIdx > totalRules {
					endIdx = totalRules
				}

				// Create a new WazuhGroup for this part
				partRules := &types.WazuhGroup{
					Rules: xmlRules.Rules[startIdx:endIdx],
				}

				// Create filename with part number and ID prefix
				filename := fmt.Sprintf("%d-sigma_%s_part%d.xml", startId, product, part+1)

				// Write the part file
				if err := writeXmlFile(filename, partRules, c); err != nil {
					utils.LogIt(utils.ERROR, fmt.Sprintf("Failed to write %s", filename), err, c.Info, c.Debug)
					continue
				}

				fmt.Printf("  Created %s with %d rules\n", filename, len(partRules.Rules))
			}
		} else {
			// Write single file (no splitting needed) with ID prefix
			filename := fmt.Sprintf("%d-sigma_%s.xml", startId, product)

			if err := writeXmlFile(filename, xmlRules, c); err != nil {
				utils.LogIt(utils.ERROR, fmt.Sprintf("Failed to write %s", filename), err, c.Info, c.Debug)
				continue
			}

			fmt.Printf("Created %s with %d rules\n", filename, len(xmlRules.Rules))
		}
	}
}

// writeXmlFile writes a WazuhGroup to an XML file
func writeXmlFile(filename string, xmlRules *types.WazuhGroup, c *types.Config) error {
	// Create the file
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Add XML header comment
	xmlRules.Header = xml.Comment(`
	Author: Brian Kellogg
	Sigma: https://github.com/SigmaHQ/sigma
	Wazuh: https://wazuh.com
	All Sigma rules licensed under DRL: https://github.com/SigmaHQ/Detection-Rule-License `)

	// Create an XML encoder
	enc := xml.NewEncoder(file)
	enc.Indent("", "  ")

	// Encode the rule struct to XML
	if err := enc.Encode(xmlRules); err != nil {
		return err
	}

	if _, err := file.WriteString("\n"); err != nil {
		return err
	}

	return nil
}

// WriteCDBLists writes all CDB list files to disk
func WriteCDBLists(c *types.Config) {
	utils.LogIt(utils.DEBUG, "", nil, c.Info, c.Debug)

	if len(c.CDBLists) == 0 {
		return
	}

	// Create lists directory if it doesn't exist
	listsDir := "lists"
	if err := os.MkdirAll(listsDir, 0755); err != nil {
		utils.LogIt(utils.ERROR, fmt.Sprintf("Failed to create lists directory: %s", listsDir), err, c.Info, c.Debug)
		return
	}

	totalEntries := 0
	// Write each CDB list file
	for listName, values := range c.CDBLists {
		filename := filepath.Join(listsDir, listName)

		// Create the list file
		file, err := os.Create(filename)
		if err != nil {
			utils.LogIt(utils.ERROR, fmt.Sprintf("Failed to create CDB list file: %s", filename), err, c.Info, c.Debug)
			continue
		}

		// Write each value to the file
		// CDB list format: key:value
		// For match_key lookup, we just need the key
		for _, value := range values {
			_, err := file.WriteString(value + ":1\n")
			if err != nil {
				utils.LogIt(utils.ERROR, fmt.Sprintf("Failed to write to CDB list file: %s", filename), err, c.Info, c.Debug)
				break
			}
		}

		if err := file.Close(); err != nil {
			utils.LogIt(utils.ERROR, fmt.Sprintf("Failed to close CDB list file: %s", filename), err, c.Info, c.Debug)
		}

		totalEntries += len(values)
		fmt.Printf("Created CDB list %s with %d entries\n", filename, len(values))
	}

	if totalEntries > 0 {
		fmt.Printf("\nTotal CDB lists: %d with %d total entries\n", len(c.CDBLists), totalEntries)
	}
}

// WriteDeploymentInstructions generates deployment scripts and configuration files
func WriteDeploymentInstructions(c *types.Config) {
	utils.LogIt(utils.DEBUG, "", nil, c.Info, c.Debug)

	if len(c.CDBLists) == 0 {
		return
	}

	// Generate ossec.conf snippet
	ossecConfFile := "WAZUH_CDB_CONFIG.txt"
	file, err := os.Create(ossecConfFile)
	if err != nil {
		utils.LogIt(utils.ERROR, fmt.Sprintf("Failed to create ossec.conf snippet file: %s", ossecConfFile), err, c.Info, c.Debug)
		return
	}
	defer file.Close()

	file.WriteString("# ============================================================\n")
	file.WriteString("# Wazuh CDB Lists Configuration\n")
	file.WriteString("# Add these lines to /var/ossec/etc/ossec.conf in <ruleset>\n")
	file.WriteString("# ============================================================\n\n")
	file.WriteString("<ruleset>\n")
	file.WriteString("  <!-- Your existing rules configuration -->\n")
	file.WriteString("  <!-- ... -->\n\n")
	file.WriteString("  <!-- Sigma-generated CDB Lists -->\n")

	// Sort list names for consistent output
	listNames := make([]string, 0, len(c.CDBLists))
	for listName := range c.CDBLists {
		listNames = append(listNames, listName)
	}

	for _, listName := range listNames {
		file.WriteString(fmt.Sprintf("  <list>etc/lists/%s</list>\n", listName))
	}

	file.WriteString("</ruleset>\n")

	// Generate deployment script
	deployScript := "deploy_cdb_lists.sh"
	scriptFile, err := os.Create(deployScript)
	if err != nil {
		utils.LogIt(utils.ERROR, fmt.Sprintf("Failed to create deployment script: %s", deployScript), err, c.Info, c.Debug)
		return
	}
	defer scriptFile.Close()

	scriptFile.WriteString("#!/bin/bash\n")
	scriptFile.WriteString("# Wazuh CDB Lists Deployment Script\n")
	scriptFile.WriteString("# Generated by StoW (Sigma to Wazuh Converter)\n\n")
	scriptFile.WriteString("set -e  # Exit on error\n\n")
	scriptFile.WriteString("WAZUH_SERVER=\"${1:-localhost}\"\n")
	scriptFile.WriteString("WAZUH_USER=\"${2:-root}\"\n\n")
	scriptFile.WriteString("echo \"=======================================\"\n")
	scriptFile.WriteString("echo \"Wazuh CDB Lists Deployment\"\n")
	scriptFile.WriteString("echo \"=======================================\"\n")
	scriptFile.WriteString("echo \"Target server: $WAZUH_SERVER\"\n")
	scriptFile.WriteString("echo \"User: $WAZUH_USER\"\n")
	scriptFile.WriteString("echo \"\"\n\n")
	scriptFile.WriteString("# Step 1: Copy CDB list files\n")
	scriptFile.WriteString("echo \"[1/4] Copying CDB list files...\"\n")
	scriptFile.WriteString("if [ \"$WAZUH_SERVER\" = \"localhost\" ]; then\n")
	scriptFile.WriteString("  cp -v lists/* /var/ossec/etc/lists/\n")
	scriptFile.WriteString("else\n")
	scriptFile.WriteString("  scp -r lists/* $WAZUH_USER@$WAZUH_SERVER:/var/ossec/etc/lists/\n")
	scriptFile.WriteString("fi\n\n")
	scriptFile.WriteString("# Step 2: Copy XML rule files\n")
	scriptFile.WriteString("echo \"[2/4] Copying Sigma rule files...\"\n")
	scriptFile.WriteString("if [ \"$WAZUH_SERVER\" = \"localhost\" ]; then\n")
	scriptFile.WriteString("  cp -v *-sigma_*.xml *-sysmon_*.xml /var/ossec/etc/rules/\n")
	scriptFile.WriteString("else\n")
	scriptFile.WriteString("  scp *-sigma_*.xml *-sysmon_*.xml $WAZUH_USER@$WAZUH_SERVER:/var/ossec/etc/rules/\n")
	scriptFile.WriteString("fi\n\n")
	scriptFile.WriteString("# Step 3: Set permissions\n")
	scriptFile.WriteString("echo \"[3/4] Setting permissions...\"\n")
	scriptFile.WriteString("if [ \"$WAZUH_SERVER\" = \"localhost\" ]; then\n")
	scriptFile.WriteString("  chown wazuh:wazuh /var/ossec/etc/lists/sigma_*\n")
	scriptFile.WriteString("  chown wazuh:wazuh /var/ossec/etc/rules/*-sigma_*.xml /var/ossec/etc/rules/*-sysmon_*.xml\n")
	scriptFile.WriteString("  chmod 640 /var/ossec/etc/lists/sigma_*\n")
	scriptFile.WriteString("  chmod 640 /var/ossec/etc/rules/*-sigma_*.xml /var/ossec/etc/rules/*-sysmon_*.xml\n")
	scriptFile.WriteString("else\n")
	scriptFile.WriteString("  ssh $WAZUH_USER@$WAZUH_SERVER \"chown wazuh:wazuh /var/ossec/etc/lists/sigma_* && chown wazuh:wazuh /var/ossec/etc/rules/*-sigma_*.xml /var/ossec/etc/rules/*-sysmon_*.xml && chmod 640 /var/ossec/etc/lists/sigma_* && chmod 640 /var/ossec/etc/rules/*-sigma_*.xml /var/ossec/etc/rules/*-sysmon_*.xml\"\n")
	scriptFile.WriteString("fi\n\n")
	scriptFile.WriteString("echo \"[4/4] CDB lists will be compiled automatically on Wazuh restart\"\n")
	scriptFile.WriteString("echo \"\"\n")
	scriptFile.WriteString("echo \"=======================================\"\n")
	scriptFile.WriteString("echo \"IMPORTANT: Manual Steps Required\"\n")
	scriptFile.WriteString("echo \"=======================================\"\n")
	scriptFile.WriteString("echo \"1. Edit /var/ossec/etc/ossec.conf and add the <list> entries\"\n")
	scriptFile.WriteString("echo \"   See WAZUH_CDB_CONFIG.txt for the configuration\"\n")
	scriptFile.WriteString("echo \"\"\n")
	scriptFile.WriteString("echo \"2. Add the Sigma rule files to ossec.conf:\"\n")
	scriptFile.WriteString("echo \"   <ruleset>\"\n")

	// Find all generated sigma and sysmon XML files (including part files)
	xmlFiles, err := filepath.Glob("*-sigma_*.xml")
	if err != nil {
		utils.LogIt(utils.ERROR, "Failed to find generated Sigma XML files", err, c.Info, c.Debug)
	}

	sysmonFiles, err2 := filepath.Glob("*-sysmon_*.xml")
	if err2 != nil {
		utils.LogIt(utils.ERROR, "Failed to find generated Sysmon XML files", err2, c.Info, c.Debug)
	}

	// Combine and sort for consistent output
	allXMLFiles := append(xmlFiles, sysmonFiles...)
	if len(allXMLFiles) > 0 {
		for _, xmlFile := range allXMLFiles {
			scriptFile.WriteString(fmt.Sprintf("echo \"     <include>%s</include>\"\n", filepath.Base(xmlFile)))
		}
	}

	scriptFile.WriteString("echo \"   </ruleset>\"\n")
	scriptFile.WriteString("echo \"\"\n")
	scriptFile.WriteString("echo \"3. Restart Wazuh manager:\"\n")
	scriptFile.WriteString("echo \"   systemctl restart wazuh-manager\"\n")
	scriptFile.WriteString("echo \"\"\n")
	scriptFile.WriteString("echo \"   OR remotely:\"\n")
	scriptFile.WriteString("echo \"   ssh $WAZUH_USER@$WAZUH_SERVER 'systemctl restart wazuh-manager'\"\n")
	scriptFile.WriteString("echo \"\"\n")
	scriptFile.WriteString("echo \"=======================================\"\n")
	scriptFile.WriteString("echo \"Deployment files ready!\"\n")
	scriptFile.WriteString("echo \"=======================================\"\n")

	// Make script executable
	os.Chmod(deployScript, 0755)

	fmt.Printf("\n")
	fmt.Printf("==============================================================================\n")
	fmt.Printf("CDB LISTS DEPLOYMENT INSTRUCTIONS\n")
	fmt.Printf("==============================================================================\n")
	fmt.Printf("\n")
	fmt.Printf("✓ Created %d CDB list files in lists/ directory\n", len(c.CDBLists))
	fmt.Printf("✓ Created deployment script: %s\n", deployScript)
	fmt.Printf("✓ Created ossec.conf configuration: %s\n", ossecConfFile)
	fmt.Printf("\n")
	fmt.Printf("DEPLOYMENT STEPS:\n")
	fmt.Printf("\n")
	fmt.Printf("1. Run the deployment script:\n")
	fmt.Printf("   Local:  sudo ./%s localhost\n", deployScript)
	fmt.Printf("   Remote: ./%s <wazuh-server-ip> <user>\n", deployScript)
	fmt.Printf("\n")
	fmt.Printf("2. Add CDB list declarations to /var/ossec/etc/ossec.conf:\n")
	fmt.Printf("   See %s for the exact configuration\n", ossecConfFile)
	fmt.Printf("\n")
	fmt.Printf("3. Restart Wazuh manager:\n")
	fmt.Printf("   sudo systemctl restart wazuh-manager\n")
	fmt.Printf("\n")
	fmt.Printf("NOTES:\n")
	fmt.Printf("• Modern Wazuh (v3.11.0+) compiles CDB lists automatically on startup\n")
	fmt.Printf("• No need to run wazuh-makelists manually\n")
	fmt.Printf("• CDB lists provide O(1) lookup time for large datasets\n")
	fmt.Printf("\n")
	fmt.Printf("==============================================================================\n")
}

// GenerateLinuxParentRules creates the base auditd parent rules for Linux
func GenerateLinuxParentRules() []types.WazuhRule {
	return []types.WazuhRule{
		{
			ID:          "210000",
			Level:       "3",
			DecodedAs:   "auditd-syscall",
			Description: "Audit: SYSCALL Messages grouped.",
			Options:     []string{"no_full_log"},
			Groups:      "linux,auditd,syscall,",
		},
		{
			ID:          "210001",
			Level:       "3",
			DecodedAs:   "auditd-execve",
			Description: "Audit: EXECVE Messages grouped.",
			Options:     []string{"no_full_log"},
			Groups:      "linux,auditd,execve,",
		},
		{
			ID:          "210002",
			Level:       "3",
			DecodedAs:   "auditd-path",
			Description: "Audit: PATH Messages grouped.",
			Options:     []string{"no_full_log"},
			Groups:      "linux,auditd,path,",
		},
		{
			ID:          "210003",
			Level:       "5",
			DecodedAs:   "auditd-config_change",
			Description: "Audit: CONFIG_CHANGE Messages grouped.",
			Options:     []string{"no_full_log"},
			Groups:      "linux,auditd,config_change,",
		},
		{
			ID:          "210004",
			Level:       "3",
			DecodedAs:   "auditd-user_and_cred",
			Description: "Audit: USER credentials Messages grouped.",
			Options:     []string{"no_full_log"},
			Groups:      "linux,auditd,user_and_cred,",
		},
		{
			ID:          "210005",
			Level:       "3",
			DecodedAs:   "auditd-service_stop",
			Description: "Audit: SERVICE_STOP Messages grouped.",
			Options:     []string{"no_full_log"},
			Groups:      "linux,auditd,service_stop,",
		},
		{
			ID:          "210006",
			Level:       "3",
			DecodedAs:   "auditd-tty",
			Description: "Audit: TTY/USER_TTY Messages grouped.",
			Options:     []string{"no_full_log"},
			Groups:      "linux,auditd,tty,",
		},
	}
}

// GeneratePowerShellParentRules creates PowerShell-specific parent rules for Windows
func GeneratePowerShellParentRules() []types.WazuhRule {
	return []types.WazuhRule{
		{
			ID:          "200000",
			Level:       "3",
			Description: "PowerShell: Script Block Logging (Event 4104)",
			Options:     []string{"no_full_log"},
			Groups:      "windows,powershell,ps_script,",
			Fields: []types.Field{
				{Name: "win.system.eventID", Value: "4104", Type: ""},
				{Name: "win.system.channel", Value: "Microsoft-Windows-PowerShell/Operational", Type: ""},
			},
		},
		{
			ID:          "200001",
			Level:       "3",
			Description: "PowerShell: Module Logging (Event 4103)",
			Options:     []string{"no_full_log"},
			Groups:      "windows,powershell,ps_module,",
			Fields: []types.Field{
				{Name: "win.system.eventID", Value: "4103", Type: ""},
				{Name: "win.system.channel", Value: "Microsoft-Windows-PowerShell/Operational", Type: ""},
			},
		},
		{
			ID:          "200002",
			Level:       "3",
			Description: "PowerShell: Classic Provider Start (Event 400)",
			Options:     []string{"no_full_log"},
			Groups:      "windows,powershell,ps_classic,",
			Fields: []types.Field{
				{Name: "win.system.eventID", Value: "400", Type: ""},
				{Name: "win.system.channel", Value: "Windows PowerShell", Type: ""},
			},
		},
		{
			ID:          "200003",
			Level:       "3",
			Description: "PowerShell: Classic Provider Stop (Event 403)",
			Options:     []string{"no_full_log"},
			Groups:      "windows,powershell,ps_classic,",
			Fields: []types.Field{
				{Name: "win.system.eventID", Value: "403", Type: ""},
				{Name: "win.system.channel", Value: "Windows PowerShell", Type: ""},
			},
		},
		{
			ID:          "200004",
			Level:       "5",
			Description: "PowerShell: Classic Command Start (Event 600)",
			Options:     []string{"no_full_log"},
			Groups:      "windows,powershell,ps_classic,",
			Fields: []types.Field{
				{Name: "win.system.eventID", Value: "600", Type: ""},
				{Name: "win.system.channel", Value: "Windows PowerShell", Type: ""},
			},
		},
	}
}

// GenerateWindowsEventParentRules creates Windows Event ID-specific parent rules
func GenerateWindowsEventParentRules() []types.WazuhRule {
	return []types.WazuhRule{
		{
			ID:          "200100",
			Level:       "3",
			Description: "Windows Security: Service Installation (Event 4697)",
			Options:     []string{"no_full_log"},
			Groups:      "windows,security,service_install,",
			Fields: []types.Field{
				{Name: "win.system.eventID", Value: "4697", Type: ""},
				{Name: "win.system.channel", Value: "Security", Type: ""},
			},
		},
		{
			ID:          "200101",
			Level:       "3",
			Description: "Windows System: Service Installation (Event 7045)",
			Options:     []string{"no_full_log"},
			Groups:      "windows,system,service_install,",
			Fields: []types.Field{
				{Name: "win.system.eventID", Value: "7045", Type: ""},
				{Name: "win.system.channel", Value: "System", Type: ""},
			},
		},
		{
			ID:          "200102",
			Level:       "3",
			Description: "Windows Security: Network Share Object Access (Event 5145)",
			Options:     []string{"no_full_log"},
			Groups:      "windows,security,share_access,",
			Fields: []types.Field{
				{Name: "win.system.eventID", Value: "5145", Type: ""},
				{Name: "win.system.channel", Value: "Security", Type: ""},
			},
		},
		{
			ID:          "200103",
			Level:       "3",
			Description: "Windows Security: Successful Account Logon (Event 4624)",
			Options:     []string{"no_full_log"},
			Groups:      "windows,security,logon,",
			Fields: []types.Field{
				{Name: "win.system.eventID", Value: "4624", Type: ""},
				{Name: "win.system.channel", Value: "Security", Type: ""},
			},
		},
	}
}
