package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/ArtanisInc/StoW/pkg/config"
	"github.com/ArtanisInc/StoW/pkg/converter"
	"github.com/ArtanisInc/StoW/pkg/generator"
	"github.com/ArtanisInc/StoW/pkg/types"
	"github.com/ArtanisInc/StoW/pkg/utils"
	"gopkg.in/yaml.v3"
)

func main() {
	// Load configuration
	c, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Parse command line arguments
	c.Info, c.Debug = getArgs(os.Args, c)
	utils.LogIt(utils.DEBUG, "", nil, c.Info, c.Debug)

	// Validate configuration
	if err := validateConfig(c); err != nil {
		log.Fatalf("Configuration validation failed: %v\nPlease fix the configuration errors and try again.", err)
	}

	// Initialize XmlRules map for multiple products
	c.Wazuh.XmlRules = make(map[string]*types.WazuhGroup)

	// Initialize CDB Lists map
	c.CDBLists = make(map[string][]string)

	// Walk Sigma rules directory and convert
	sigmaRuleIds := walkAndConvertSigmaRules(c)

	// Write XML rule files (one per product)
	generator.WriteWazuhXmlRules(c)

	// Write Windows Built-in Channel parent rules (separate file)
	generator.WriteWindowsBuiltinChannelParentRules(c)

	// Write CDB list files
	generator.WriteCDBLists(c)

	// Write deployment instructions and helper scripts
	generator.WriteDeploymentInstructions(c)

	// Save Sigma to Wazuh ID mapping
	jsonData, err := json.Marshal(c.Ids.SigmaToWazuh)
	if err != nil {
		utils.LogIt(utils.ERROR, "", err, c.Info, c.Debug)
	}
	if err := os.WriteFile(c.Wazuh.RuleIdFile, jsonData, 0644); err != nil {
		utils.LogIt(utils.ERROR, "", err, c.Info, c.Debug)
	}

	// Print conversion statistics
	printStats(c, sigmaRuleIds)
}

// walkAndConvertSigmaRules walks the Sigma rules directory and converts all rules
func walkAndConvertSigmaRules(c *types.Config) []string {
	var sigmaRuleIds []string

	err := filepath.Walk(c.Sigma.RulesRoot, func(path string, f os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-YAML files
		if f.IsDir() || !strings.HasSuffix(path, ".yml") {
			return nil
		}

		// Read and parse the Sigma rule
		data, err := os.ReadFile(path)
		if err != nil {
			utils.LogIt(utils.ERROR, "", err, c.Info, c.Debug)
			return nil
		}

		utils.LogIt(utils.INFO, path, nil, c.Info, c.Debug)

		relPath, err := filepath.Rel(c.Sigma.RulesRoot, path)
		if err != nil {
			utils.LogIt(utils.ERROR, "", err, c.Info, c.Debug)
			relPath = path
		}
		url := c.Sigma.BaseUrl + "/" + filepath.ToSlash(relPath)

		var sigmaRule types.SigmaRule
		if err := yaml.Unmarshal(data, &sigmaRule); err != nil {
			utils.LogIt(utils.ERROR, "", err, c.Info, c.Debug)
			c.TrackSkips.ErrorCount++
			return nil
		}

		// Track unique Sigma rule IDs
		if !slices.Contains(sigmaRuleIds, sigmaRule.ID) {
			sigmaRuleIds = append(sigmaRuleIds, sigmaRule.ID)
		}

		// Check if rule should be skipped
		if skipSigmaRule(&sigmaRule, c) {
			return nil
		}

		// Check for timeframe (not supported)
		detectionBytes, _ := yaml.Marshal(sigmaRule.Detection)
		detectionString := string(detectionBytes)
		if strings.Contains(detectionString, "timeframe:") {
			utils.LogIt(utils.INFO, "Skip Sigma rule timeframe: "+sigmaRule.ID, nil, c.Info, c.Debug)
			c.TrackSkips.TimeframeSkips++
			c.TrackSkips.RulesSkipped++
			return nil
		}

		// Get top-level detection logic
		detections := getTopLevelLogicCondition(sigmaRule, c)
		condition, ok := detections["condition"].(string)
		if !ok {
			utils.LogIt(utils.ERROR, "condition is not a string", nil, c.Info, c.Debug)
			return nil
		}

		// Preprocess and convert condition to DNF
		condition = converter.FixupCondition(condition)
		condition = converter.PreprocessCondition(condition, detections)
		passingSets := converter.ConvertToDNF(condition)

		// Process DNF sets and build Wazuh rules
		converter.ProcessDnfSets(passingSets, detections, &sigmaRule, url, c)

		return nil
	})

	if err != nil {
		utils.LogIt(utils.ERROR, c.Sigma.RulesRoot, err, c.Info, c.Debug)
	}

	return sigmaRuleIds
}

// skipSigmaRule checks if a Sigma rule should be skipped
func skipSigmaRule(sigma *types.SigmaRule, c *types.Config) bool {
	utils.LogIt(utils.DEBUG, "", nil, c.Info, c.Debug)

	// Check if rule is explicitly skipped
	if slices.Contains(c.Sigma.SkipIds, strings.ToLower(sigma.ID)) {
		utils.LogIt(utils.INFO, "Skip Sigma rule ID: "+sigma.ID, nil, c.Info, c.Debug)
		c.TrackSkips.HardSkipped++
		c.TrackSkips.RulesSkipped++
		return true
	}

	// Check rule status
	lowerRuleStatus := make([]string, len(c.Sigma.RuleStatus))
	for i, s := range c.Sigma.RuleStatus {
		lowerRuleStatus[i] = strings.ToLower(s)
	}
	if !slices.Contains(lowerRuleStatus, strings.ToLower(sigma.Status)) {
		utils.LogIt(utils.INFO, "Skip Sigma rule status: "+sigma.ID, nil, c.Info, c.Debug)
		c.TrackSkips.ExperimentalSkips++
		c.TrackSkips.RulesSkipped++
		return true
	}

	// If ConvertAll is true, convert all rules that are not explicitly skipped
	if c.Sigma.ConvertAll {
		return false
	}

	// If no specific conversion criteria are set, convert all rules
	if len(c.Sigma.ConvertCategories) == 0 && len(c.Sigma.ConvertServices) == 0 && len(c.Sigma.ConvertProducts) == 0 {
		return false
	}

	// Check if the rule matches any of the conversion criteria
	if slices.Contains(c.Sigma.ConvertCategories, strings.ToLower(sigma.LogSource.Category)) {
		return false
	}
	if slices.Contains(c.Sigma.ConvertServices, strings.ToLower(sigma.LogSource.Service)) {
		return false
	}
	if slices.Contains(c.Sigma.ConvertProducts, strings.ToLower(sigma.LogSource.Product)) {
		return false
	}

	// If we are here, it means the rule does not match any of the conversion criteria
	utils.LogIt(utils.INFO, "Skip Sigma rule default: "+sigma.ID, nil, c.Info, c.Debug)
	c.TrackSkips.RulesSkipped++
	return true
}

// getTopLevelLogicCondition extracts the detection map from a Sigma rule
func getTopLevelLogicCondition(sigma types.SigmaRule, c *types.Config) map[string]any {
	utils.LogIt(utils.DEBUG, "", nil, c.Info, c.Debug)
	detections := make(map[string]any)
	v := reflect.ValueOf(sigma.Detection)
	for _, k := range v.MapKeys() {
		value := v.MapIndex(k)
		key := k.Interface().(string)
		detections[key] = value.Interface()
	}
	return detections
}

// validateConfig checks if required configuration values are set and valid
func validateConfig(c *types.Config) error {
	// Validate Sigma configuration
	if c.Sigma.RulesRoot == "" {
		return fmt.Errorf("Sigma RulesRoot cannot be empty")
	}

	if err := validateFilePath(c.Sigma.RulesRoot, true); err != nil {
		return fmt.Errorf("invalid Sigma RulesRoot: %w", err)
	}

	// Validate Wazuh configuration
	if c.Wazuh.RuleIdStart < 0 {
		return fmt.Errorf("Wazuh RuleIdStart must be non-negative, got: %d", c.Wazuh.RuleIdStart)
	}

	if c.Wazuh.MaxRulesPerFile < 0 {
		return fmt.Errorf("Wazuh MaxRulesPerFile must be non-negative, got: %d", c.Wazuh.MaxRulesPerFile)
	}

	// Validate product-specific rule ID ranges don't overlap
	if len(c.Wazuh.ProductRuleIdStart) > 0 {
		usedRanges := make(map[int]string)
		for product, startId := range c.Wazuh.ProductRuleIdStart {
			if startId < 0 {
				return fmt.Errorf("product %s has negative rule ID start: %d", product, startId)
			}
			// Check for overlaps (assuming 10000 IDs per product)
			rangeStart := startId / 10000
			if existingProduct, exists := usedRanges[rangeStart]; exists {
				return fmt.Errorf("product %s rule ID range overlaps with %s", product, existingProduct)
			}
			usedRanges[rangeStart] = product
		}
	}

	return nil
}

// validateFilePath checks if a file path is valid and accessible
func validateFilePath(path string, shouldExist bool) error {
	if path == "" {
		return fmt.Errorf("file path cannot be empty")
	}

	// Clean the path to prevent directory traversal
	cleanPath := filepath.Clean(path)

	if shouldExist {
		info, err := os.Stat(cleanPath)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("path does not exist: %s", cleanPath)
			}
			return fmt.Errorf("cannot access path %s: %w", cleanPath, err)
		}

		// Additional check: ensure it's not a directory when we expect a file
		if info.IsDir() && filepath.Ext(cleanPath) != "" {
			return fmt.Errorf("expected file but got directory: %s", cleanPath)
		}
	}

	return nil
}

// printStats prints conversion statistics
func printStats(c *types.Config, sigmaRuleIds []string) {
	convertedSigmaRules := len(c.Ids.SigmaToWazuh)

	// Count total Wazuh rules across all products
	totalWazuhRules := 0
	for product, xmlRules := range c.Wazuh.XmlRules {
		ruleCount := len(xmlRules.Rules)
		totalWazuhRules += ruleCount
		fmt.Printf("Product %s: %d Wazuh rules\n", product, ruleCount)
	}

	fmt.Printf("\n\n***************************************************************************\n")
	fmt.Printf(" Number of Sigma Experimental rules skipped: %d\n", c.TrackSkips.ExperimentalSkips)
	fmt.Printf("    Number of Sigma TIMEFRAME rules skipped: %d\n", c.TrackSkips.TimeframeSkips)
	fmt.Printf("        Number of Sigma PAREN rules skipped: %d\n", c.TrackSkips.ParenSkips)
	fmt.Printf("         Number of Sigma CIDR rules skipped: %d\n", c.TrackSkips.Cidr)
	fmt.Printf("         Number of Sigma NEAR rules skipped: %d\n", c.TrackSkips.NearSkips)
	fmt.Printf("       Number of Sigma CONFIG rules skipped: %d\n", c.TrackSkips.HardSkipped)
	fmt.Printf("   Number of Sigma FIELD TOO LONG skipped: %d\n", c.TrackSkips.FieldTooLong)
	fmt.Printf("Number of Sigma rules CONVERTED TO CDB: %d\n", c.TrackSkips.ConvertedToCDB)
	fmt.Printf("   Number of INTELLIGENT FIELD MAPPINGS: %d\n", c.TrackSkips.IntelligentMappings)
	fmt.Printf("        Number of Sigma ERROR rules skipped: %d\n", c.TrackSkips.ErrorCount)
	fmt.Printf("---------------------------------------------------------------------------\n")
	fmt.Printf("                  Total Sigma rules skipped: %d\n", c.TrackSkips.RulesSkipped)
	fmt.Printf("                Total Sigma rules converted: %d\n", convertedSigmaRules)
	fmt.Printf("---------------------------------------------------------------------------\n")
	fmt.Printf("                  Total Wazuh rules created: %d\n", totalWazuhRules)
	fmt.Printf("---------------------------------------------------------------------------\n")
	fmt.Printf("                          Total Sigma rules: %d\n", len(sigmaRuleIds))
	if len(sigmaRuleIds) > 0 {
		fmt.Printf("                    Sigma rules converted %%: %.2f\n", float64(convertedSigmaRules)/float64(len(sigmaRuleIds))*100)
	}
	fmt.Printf("***************************************************************************\n\n")
}

// getArgs parses command line arguments
func getArgs(args []string, c *types.Config) (bool, bool) {
	utils.LogIt(utils.DEBUG, "", nil, c.Info, c.Debug)
	if len(args) == 1 {
		return c.Info, c.Debug
	}
	infoArgs := []string{"-i", "--info"}
	debugArgs := []string{"-d", "--debug"}
	for _, arg := range args {
		switch {
		case slices.Contains(infoArgs, arg):
			c.Info = true
		case slices.Contains(debugArgs, arg):
			c.Info = true
			c.Debug = true
		}
	}
	return c.Info, c.Debug
}
