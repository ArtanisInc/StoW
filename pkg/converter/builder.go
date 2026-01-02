package converter

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/ArtanisInc/StoW/pkg/bridge"
	"github.com/ArtanisInc/StoW/pkg/strategy"
	"github.com/ArtanisInc/StoW/pkg/types"
	"github.com/ArtanisInc/StoW/pkg/utils"
)

// BuildRule constructs a Wazuh rule from a Sigma rule detection
func BuildRule(sigma *types.SigmaRule, url string, product string, c *types.Config, detections map[string]any, selectionNegations map[string]bool) types.WazuhRule {
	utils.LogIt(utils.DEBUG, "", nil, c.Info, c.Debug)

	ruleFields := GetFields(detections, sigma, c, selectionNegations)
	if len(ruleFields.Fields) == 0 && len(ruleFields.SrcIps) == 0 && len(ruleFields.DstIps) == 0 {
		utils.LogIt(utils.WARN, "No fields found for rule: "+sigma.ID+" URL: "+url, nil, c.Info, c.Debug)
		return types.WazuhRule{}
	}

	// Process oversized fields, converting to CDB lists if needed
	finalFields, listFields, err := processOversizedFields(ruleFields, sigma.ID, c)
	if err != nil {
		return types.WazuhRule{}
	}

	// Update ruleFields with the processed fields
	ruleFields.Fields = finalFields
	ruleFields.ListFields = listFields

	// Build the Wazuh rule
	var rule types.WazuhRule
	populateRuleMetadata(&rule, sigma, url, product, c)

	// Assign detection fields
	rule.Fields = ruleFields.Fields
	rule.SrcIps = ruleFields.SrcIps
	rule.DstIps = ruleFields.DstIps
	rule.Lists = ruleFields.ListFields

	// Optimize Linux rules: Convert audit.type fields to if_sid
	if product == "linux" {
		optimizeLinuxRule(&rule)
	}

	// Optimize Windows rules: Convert generic channel fallback to EventID-specific parent rules
	if product == "windows" {
		optimizeWindowsEventRule(&rule)
	}

	return rule
}

// GetFields extracts all fields from a detection map
func GetFields(detection map[string]any, sigma *types.SigmaRule, c *types.Config, selectionNegations map[string]bool) types.RuleFields {
	utils.LogIt(utils.INFO, fmt.Sprintf("GetFields detection: %v", detection), nil, c.Info, c.Debug)
	var fields []types.Field
	var srcIps []types.IPField
	var dstIps []types.IPField

	for selectionKey, selectionVal := range detection {
		if selectionMap, ok := selectionVal.(map[string]any); ok {
			for key, value := range selectionMap {
				processDetectionField(selectionKey, key, value, sigma, c, &fields, &srcIps, &dstIps, selectionNegations)
			}
		} else if selectionList, ok := selectionVal.([]any); ok {
			// Handle list of strings
			var stringList []string
			for _, item := range selectionList {
				if str, ok := item.(string); ok {
					stringList = append(stringList, str)
				}
			}
			if len(stringList) == len(selectionList) {
				processDetectionField(selectionKey, "", stringList, sigma, c, &fields, &srcIps, &dstIps, selectionNegations)
				continue
			}

			for _, item := range selectionList {
				if itemMap, ok := item.(map[string]any); ok {
					for key, value := range itemMap {
						processDetectionField(selectionKey, key, value, sigma, c, &fields, &srcIps, &dstIps, selectionNegations)
					}
				}
			}
		} else if value, ok := selectionVal.(string); ok {
			processDetectionField(selectionKey, "", value, sigma, c, &fields, &srcIps, &dstIps, selectionNegations)
		}
	}
	utils.LogIt(utils.INFO, fmt.Sprintf("GetFields fields: %v, srcIps: %v, dstIps: %v", fields, srcIps, dstIps), nil, c.Info, c.Debug)
	return types.RuleFields{
		Fields: fields,
		SrcIps: srcIps,
		DstIps: dstIps,
	}
}

// processDetectionField extracts and processes a single field from a Sigma detection
func processDetectionField(selectionKey string, key string, value any, sigma *types.SigmaRule, c *types.Config, fields *[]types.Field, srcIps *[]types.IPField, dstIps *[]types.IPField, selectionNegations map[string]bool) {
	utils.LogIt(utils.INFO, fmt.Sprintf("processDetectionField key: %s, value: %v", key, value), nil, c.Info, c.Debug)

	// Parse field name and modifiers
	parts := strings.Split(key, "|")
	fieldName := parts[0]
	mods, value := ParseFieldModifiers(parts, value)

	wazuhField := bridge.ConvertFieldName(fieldName, sigma, c)

	// Apply intelligent field mapping if we got "full_log" as fallback
	// and we have enough context to make a better guess
	if wazuhField == "full_log" && sigma != nil {
		values := getFieldValues(value, fieldName, c)
		utils.LogIt(utils.DEBUG, fmt.Sprintf("[Intelligent Mapping] wazuhField=%s, fieldName='%s', values=%v, product=%s, category=%s",
			wazuhField, fieldName, values, sigma.LogSource.Product, sigma.LogSource.Category), nil, c.Info, c.Debug)

		if len(values) > 0 {
			// Try intelligent mapping with the first value
			guessedField := intelligentFieldMapping(fieldName, values[0], sigma, c)
			if guessedField != "" {
				wazuhField = guessedField
				// Use WARN to ensure it's always visible
				fmt.Printf("✓ Intelligent mapping applied: fieldName='%s', value='%s' → %s\n", fieldName, values[0], wazuhField)
				utils.LogIt(utils.INFO, fmt.Sprintf("Intelligent mapping: '%s'='%s' → %s", fieldName, values[0], wazuhField), nil, c.Info, c.Debug)
			}
		}
	}

	field := types.Field{
		Name: wazuhField,
		Type: "pcre2",
	}

	// Apply negation if this selectionKey is marked as negated
	if selectionNegations[selectionKey] {
		field.Negate = "yes"
	}

	// Handle CIDR modifier for IP fields
	if mods.IsCIDR {
		values := getFieldValues(value, fieldName, c)
		handleCIDRField(fieldName, values, selectionKey, selectionNegations, srcIps, dstIps, c)
		return
	}

	values := getFieldValues(value, fieldName, c)

	// Check if we can use exact field matching instead of regex
	canUseExact := !mods.IsRegex && !mods.StartsWith && !mods.EndsWith && !mods.IsBase64
	if canUseExact {
		for _, v := range values {
			if !IsSimpleValue(v) {
				canUseExact = false
				break
			}
		}
	}

	// Handle 'all' modifier - create separate field for each value
	if mods.HasAll {
		for _, v := range values {
			// For |all groups with anonymous fields, apply intelligent mapping to EACH value individually
			// This allows different values to map to different fields (e.g., command to a0, flag to a1)
			valueWazuhField := wazuhField
			if sigma != nil && fieldName == "" {
				// Re-apply intelligent mapping for each value in the |all group
				guessedField := intelligentFieldMapping(fieldName, v, sigma, c)
				if guessedField != "" {
					valueWazuhField = guessedField
					fmt.Printf("✓ Intelligent mapping applied (|all): fieldName='%s', value='%s' → %s\n", fieldName, v, valueWazuhField)
					utils.LogIt(utils.INFO, fmt.Sprintf("Intelligent mapping (|all): '%s'='%s' → %s", fieldName, v, valueWazuhField), nil, c.Info, c.Debug)
				}
			}

			newField := field
			newField.Name = valueWazuhField  // Use the individually mapped field!

			// Use exact matching if possible
			// Windows needs case-insensitive (requires pcre2 with (?i))
			// Linux uses osmatch for maximum performance (30-40% faster than osregex)
			if canUseExact && len(values) == 1 {
				if needsCaseInsensitive(valueWazuhField, sigma.LogSource.Product) {
					// Windows: MUST use pcre2 with (?i) for case-insensitive
					newField.Type = "pcre2"
					newField.Value = "(?i)^" + escapeRegexSpecialChars(v) + "$"
				} else {
					// Linux: use osmatch for fastest exact string matching
					newField.Type = "osmatch"
					newField.Value = v  // osmatch doesn't need escaping or anchors for exact match
				}
			} else {
				newField.Value = BuildFieldValue(v, mods, valueWazuhField, sigma.LogSource.Product)
			}
			*fields = append(*fields, newField)
			utils.LogIt(utils.INFO, fmt.Sprintf("processDetectionField appended field: %v", newField), nil, c.Info, c.Debug)
		}
		return
	}

	// Build combined field value (OR logic)
	var fieldValues []string
	for _, v := range values {
		fieldValues = append(fieldValues, BuildFieldValue(v, mods, wazuhField, sigma.LogSource.Product))
	}

	if len(fieldValues) == 0 {
		utils.LogIt(utils.DEBUG, fmt.Sprintf("No processed fieldValues for field '%s'", fieldName), nil, c.Info, c.Debug)
		return
	}

	// Construct final field value
	if mods.IsRegex {
		field.Value = strings.Join(fieldValues, "|")
	} else {
		combinedValue := strings.Join(fieldValues, "|")
		if len(fieldValues) > 1 {
			combinedValue = "(?:" + combinedValue + ")"
		}
		if mods.StartsWith {
			combinedValue = "^" + combinedValue
		}
		if mods.EndsWith {
			combinedValue = combinedValue + "$"
		}
		field.Value = combinedValue
	}

	// Use exact matching for simple single values with no modifiers
	// Windows needs case-insensitive (requires pcre2 with (?i))
	// Linux uses osmatch for maximum performance (30-40% faster than osregex)
	if canUseExact && len(values) == 1 {
		if needsCaseInsensitive(wazuhField, sigma.LogSource.Product) {
			// Windows: MUST use pcre2 with (?i) for case-insensitive exact match
			field.Type = "pcre2"
			field.Value = "(?i)^" + escapeRegexSpecialChars(values[0]) + "$"
			utils.LogIt(utils.INFO, fmt.Sprintf("Using case-insensitive exact field matching for %s=%s", wazuhField, values[0]), nil, c.Info, c.Debug)
		} else {
			// Linux: use osmatch for fastest exact string matching
			field.Type = "osmatch"
			field.Value = values[0]  // osmatch doesn't need escaping or anchors for exact match
			utils.LogIt(utils.INFO, fmt.Sprintf("Using osmatch exact field matching for %s=%s", wazuhField, values[0]), nil, c.Info, c.Debug)
		}
	}

	*fields = append(*fields, field)
	utils.LogIt(utils.INFO, fmt.Sprintf("processDetectionField appended field: %v", field), nil, c.Info, c.Debug)
}

// getFieldValues extracts string values from any field value type
func getFieldValues(value any, fieldName string, c *types.Config) []string {
	var values []string
	switch v := value.(type) {
	case string:
		values = append(values, v)
	case int:
		values = append(values, strconv.Itoa(v))
	case []string:
		values = append(values, v...)
	case []any:
		for _, i := range v {
			switch iv := i.(type) {
			case string:
				values = append(values, iv)
			case int:
				values = append(values, strconv.Itoa(iv))
			}
		}
	default:
		utils.LogIt(utils.DEBUG, fmt.Sprintf("Unsupported value type for field '%s': %T", fieldName, v), nil, c.Info, c.Debug)
	}

	if len(values) == 0 {
		utils.LogIt(utils.DEBUG, fmt.Sprintf("No values extracted for field '%s'", fieldName), nil, c.Info, c.Debug)
	}
	return values
}

// ipFieldType represents the type of IP field
type ipFieldType int

const (
	ipFieldUnknown ipFieldType = iota
	ipFieldSource
	ipFieldDestination
	ipFieldGeneric
)

// determineIPFieldType identifies whether a field is a source, destination, or generic IP field
func determineIPFieldType(fieldName string) ipFieldType {
	lowerFieldName := strings.ToLower(fieldName)

	// Check for source IP patterns
	if strings.Contains(lowerFieldName, "sourceip") ||
		strings.Contains(lowerFieldName, "src_ip") ||
		strings.Contains(lowerFieldName, "srcip") ||
		strings.Contains(lowerFieldName, "clientip") ||
		strings.Contains(lowerFieldName, "clientaddress") ||
		lowerFieldName == "c-ip" {
		return ipFieldSource
	}

	// Check for destination IP patterns
	if strings.Contains(lowerFieldName, "destinationip") ||
		strings.Contains(lowerFieldName, "dst_ip") ||
		strings.Contains(lowerFieldName, "dstip") ||
		strings.Contains(lowerFieldName, "destination") {
		return ipFieldDestination
	}

	// Check for generic IP patterns
	if strings.Contains(lowerFieldName, "ipaddress") ||
		strings.Contains(lowerFieldName, "ip_address") ||
		lowerFieldName == "ipaddress" ||
		(strings.Contains(lowerFieldName, "address") && strings.Contains(lowerFieldName, "ip")) {
		return ipFieldGeneric
	}

	return ipFieldUnknown
}

// handleCIDRField processes CIDR notation IP fields and adds them to the appropriate IP field list
func handleCIDRField(fieldName string, values []string, selectionKey string, selectionNegations map[string]bool, srcIps *[]types.IPField, dstIps *[]types.IPField, c *types.Config) {
	ipType := determineIPFieldType(fieldName)

	negate := ""
	if selectionNegations[selectionKey] {
		negate = "yes"
	}

	for _, v := range values {
		ipField := types.IPField{
			Negate: negate,
			Value:  v,
		}

		switch ipType {
		case ipFieldSource:
			*srcIps = append(*srcIps, ipField)
			utils.LogIt(utils.INFO, fmt.Sprintf("Added srcip CIDR field: %s (negate=%s)", v, negate), nil, c.Info, c.Debug)
		case ipFieldDestination:
			*dstIps = append(*dstIps, ipField)
			utils.LogIt(utils.INFO, fmt.Sprintf("Added dstip CIDR field: %s (negate=%s)", v, negate), nil, c.Info, c.Debug)
		case ipFieldGeneric:
			// Generic IP field - default to srcip
			*srcIps = append(*srcIps, ipField)
			utils.LogIt(utils.INFO, fmt.Sprintf("Added srcip CIDR field (generic IP): %s (negate=%s)", v, negate), nil, c.Info, c.Debug)
		default:
			// If we can't determine IP direction, log a warning and skip
			utils.LogIt(utils.WARN, fmt.Sprintf("CIDR modifier used on non-IP field: %s", fieldName), nil, c.Info, c.Debug)
		}
	}
}

// processOversizedFields checks for fields exceeding Wazuh's size limits and converts them to CDB lists
func processOversizedFields(ruleFields types.RuleFields, sigmaID string, c *types.Config) ([]types.Field, []types.ListField, error) {
	const maxFieldLength = 4096
	var finalFields []types.Field
	var listFields []types.ListField

	for _, field := range ruleFields.Fields {
		if len(field.Value) <= maxFieldLength {
			finalFields = append(finalFields, field)
			continue
		}

		// Field exceeds limit - convert to CDB list
		values := ExtractValuesFromRegex(field.Value)

		if len(values) == 0 {
			utils.LogIt(utils.WARN, fmt.Sprintf("Rule %s has field value exceeding limit but couldn't extract values. Skipping rule.", sigmaID), nil, c.Info, c.Debug)
			c.TrackSkips.FieldTooLong++
			c.TrackSkips.RulesSkipped++
			return nil, nil, fmt.Errorf("field value too long and cannot be extracted")
		}

		// Create a CDB list name using Sigma ID and field name (deterministic, no index)
		listName := fmt.Sprintf("sigma_%s_%s", strings.ReplaceAll(sigmaID, "-", ""), SanitizeFieldName(field.Name))

		// Store the values for later CDB generation
		c.CDBLists[listName] = values

		// Create a list field instead of regular field
		listField := types.ListField{
			Field:  field.Name,
			Lookup: "match_key",
			Negate: field.Negate,
			Value:  fmt.Sprintf("etc/lists/%s", listName),
		}
		listFields = append(listFields, listField)

		utils.LogIt(utils.INFO, fmt.Sprintf("Rule %s field '%s' converted to CDB list with %d values (%d chars → CDB)", sigmaID, field.Name, len(values), len(field.Value)), nil, c.Info, c.Debug)
		c.TrackSkips.ConvertedToCDB++
	}

	return finalFields, listFields, nil
}

// populateRuleMetadata fills in the Wazuh rule metadata from Sigma rule data
func populateRuleMetadata(rule *types.WazuhRule, sigma *types.SigmaRule, url string, product string, c *types.Config) {
	rule.ID = trackIdMaps(sigma.ID, product, c)
	rule.Level = strconv.Itoa(getLevel(sigma.Level, c))
	rule.Description = sigma.Title
	rule.Info.Type = "link"
	rule.Info.Value = url

	// Sanitize fields for safe XML comment usage
	rule.Author = xml.Comment("     Author: " + sanitizeXMLComment(sigma.Author))
	rule.SigmaDescription = xml.Comment("Description: " + sanitizeXMLComment(sigma.Description))
	rule.Date = xml.Comment("    Created: " + sanitizeXMLComment(sigma.Date))
	rule.Modified = xml.Comment("   Modified: " + sanitizeXMLComment(sigma.Modified))
	rule.Status = xml.Comment("     Status: " + sanitizeXMLComment(sigma.Status))
	rule.SigmaID = xml.Comment("   Sigma ID: " + sanitizeXMLComment(sigma.ID))

	// Add MITRE ATT&CK tags if present
	filteredMitreTags := filterMitreTags(sigma.Tags)
	if len(filteredMitreTags) > 0 {
		rule.Mitre = &struct {
			IDs []string `xml:"id,omitempty"`
		}{IDs: filteredMitreTags}
	}

	// Set rule options and groups
	rule.Options = getOptions(sigma, c)
	rule.Groups = getGroups(sigma, c)

	// Set if_sid or if_group dependencies using strategy pattern
	ifType, value := bridge.GetParentRuleID(sigma, c)
	if ifType == "grp" {
		rule.IfGroup = value
	} else {
		rule.IfSid = value
	}
}

// sanitizeXMLComment removes invalid characters from XML comments
func sanitizeXMLComment(s string) string {
	if s == "" {
		return s
	}

	// Replace all occurrences of "--" with a single dash
	s = strings.ReplaceAll(s, "--", "-")

	// Ensure the comment doesn't start with "-"
	s = strings.TrimLeft(s, "-")

	// Ensure the comment doesn't end with "-"
	s = strings.TrimRight(s, "-")

	// If the string is now empty or only whitespace, return a safe default
	if strings.TrimSpace(s) == "" {
		return "N/A"
	}

	return s
}

// filterMitreTags filters and formats MITRE ATT&CK tags from Sigma rules
func filterMitreTags(tags []string) []string {
	var filtered []string

	for _, tag := range tags {
		// Remove "attack." prefix if present
		tag = strings.TrimPrefix(tag, "attack.")

		// Check if this is a technique ID (starts with 't' followed by digits)
		if len(tag) > 1 && strings.HasPrefix(strings.ToLower(tag), "t") {
			// Check if second character is a digit
			if len(tag) > 1 && tag[1] >= '0' && tag[1] <= '9' {
				// Convert to uppercase format (T1003.001)
				filtered = append(filtered, strings.ToUpper(tag))
			}
		}
	}

	return filtered
}

// trackIdMaps assigns and tracks Wazuh rule IDs for Sigma rules
func trackIdMaps(sigmaId string, product string, c *types.Config) string {
	utils.LogIt(utils.DEBUG, "", nil, c.Info, c.Debug)

	// Get the starting ID for this product, fallback to default RuleIdStart if not configured
	startId, ok := c.Wazuh.ProductRuleIdStart[product]
	if !ok {
		startId = c.Wazuh.RuleIdStart
	}

	// Has this Sigma rule been converted previously, reuse its Wazuh rule IDs
	if ids, ok := c.Ids.SigmaToWazuh[sigmaId]; ok {
		for _, id := range ids {
			if !slices.Contains(c.Ids.CurrentUsed, id) {
				c.Ids.CurrentUsed = append(c.Ids.CurrentUsed, id)
				return strconv.Itoa(id)
			}
		}
	}

	// New Sigma rule, find an unused Wazuh rule ID starting from product-specific ID
	currentId := startId
	for slices.Contains(c.Ids.PreviousUsed, currentId) ||
		slices.Contains(c.Ids.CurrentUsed, currentId) {
		currentId++
	}

	addToMapStrToInts(c, sigmaId, currentId)
	c.Ids.CurrentUsed = append(c.Ids.CurrentUsed, currentId)
	return strconv.Itoa(currentId)
}

// addToMapStrToInts adds a Sigma ID to Wazuh ID mapping
func addToMapStrToInts(c *types.Config, sigmaId string, wazuhId int) {
	utils.LogIt(utils.DEBUG, "", nil, c.Info, c.Debug)
	// If the key doesn't exist, add it to the map with a new slice
	if _, ok := c.Ids.SigmaToWazuh[sigmaId]; !ok {
		c.Ids.SigmaToWazuh[sigmaId] = []int{wazuhId}
		return
	}
	// If the key exists, append to the slice
	c.Ids.SigmaToWazuh[sigmaId] = append(c.Ids.SigmaToWazuh[sigmaId], wazuhId)
}

// getLevel converts Sigma severity level to Wazuh level
func getLevel(sigmaLevel string, c *types.Config) int {
	utils.LogIt(utils.DEBUG, "", nil, c.Info, c.Debug)
	switch strings.ToLower(sigmaLevel) {
	case "informational":
		return c.Wazuh.Levels.Informational
	case "low":
		return c.Wazuh.Levels.Low
	case "medium":
		return c.Wazuh.Levels.Medium
	case "high":
		return c.Wazuh.Levels.High
	case "critical":
		return c.Wazuh.Levels.Critical
	default:
		return c.Wazuh.Levels.Informational
	}
}

// getGroups builds the groups string from Sigma rule logsource
func getGroups(sigma *types.SigmaRule, c *types.Config) string {
	utils.LogIt(utils.DEBUG, "", nil, c.Info, c.Debug)
	var builder strings.Builder

	if sigma.LogSource.Category != "" {
		builder.WriteString(sigma.LogSource.Category)
		builder.WriteString(",")
	}
	if sigma.LogSource.Product != "" {
		builder.WriteString(sigma.LogSource.Product)
		builder.WriteString(",")
	}
	if sigma.LogSource.Service != "" {
		builder.WriteString(sigma.LogSource.Service)
		builder.WriteString(",")
	}

	return builder.String()
}

// getOptions determines Wazuh rule options based on configuration
func getOptions(sigma *types.SigmaRule, c *types.Config) string {
	utils.LogIt(utils.DEBUG, "", nil, c.Info, c.Debug)
	var options []string
	if c.Wazuh.Options.NoFullLog {
		options = append(options, "no_full_log")
	}
	if c.Wazuh.Options.EmailAlert &&
		(slices.Contains(c.Wazuh.Options.SigmaIdEmail, sigma.ID) ||
			slices.Contains(c.Wazuh.Options.EmailLevels, sigma.Level)) {
		options = append(options, "alert_by_email")
	}
	// Return comma-separated string for single <options> element
	return strings.Join(options, ",")
}

// HandleB64Offsets encodes a value with base64 offsets for matching
func HandleB64Offsets(value string) string {
	offset1 := base64.StdEncoding.EncodeToString([]byte(value))
	offset2 := base64.StdEncoding.EncodeToString([]byte(" " + value))[2:]
	offset3 := base64.StdEncoding.EncodeToString([]byte("  " + value))[3:]
	return offset1 + "|" + offset2 + "|" + offset3
}

// HandleWindash replaces dashes with character class for flexible matching
func HandleWindash(value any) any {
	switch v := value.(type) {
	case []string:
		temp := make([]string, len(v))
		for i, val := range v {
			temp[i] = strings.ReplaceAll(val, "-", "[/-]")
		}
		return temp
	case string:
		return strings.ReplaceAll(v, "-", "[/-]")
	default:
		return value
	}
}

// optimizeLinuxRule converts audit.type field matching to if_sid for better performance
func optimizeLinuxRule(rule *types.WazuhRule) {
	// Skip if rule already has if_sid (already optimized)
	if rule.IfSid != "" {
		return
	}

	// Map audit.type values to their corresponding parent rule IDs (case-insensitive)
	auditTypeToIfSid := map[string]string{
		"execve":         "210001", // auditd-execve (process execution)
		"syscall":        "210000", // auditd-syscall (system calls)
		"path":           "210002", // auditd-path (file access)
		"config_change":  "210003", // auditd-config_change
		"user_acct":      "210004", // auditd-user_and_cred
		"user_auth":      "210004", // auditd-user_and_cred
		"add_user":       "210004", // auditd-user_and_cred (user management)
		"del_user":       "210004", // auditd-user_and_cred (user management)
		"user_chauthtok": "210004", // auditd-user_and_cred (password change)
		"service_stop":   "210005", // auditd-service_stop (service management)
		"tty":            "210006", // auditd-tty (TTY/terminal events)
		"user_tty":       "210006", // auditd-tty (user TTY events)
	}

	// Look for audit.type field (exact match only, skip pcre2)
	var auditTypeValue string
	var auditTypeIndex int = -1

	for i, field := range rule.Fields {
		if field.Name == "audit.type" && field.Type != "pcre2" {
			// Found exact match audit.type field (osregex/osmatch, not pcre2)
			// Remove anchors if present (^value$)
			value := field.Value
			value = strings.TrimPrefix(value, "^")
			value = strings.TrimSuffix(value, "$")
			auditTypeValue = strings.ToLower(value) // Normalize to lowercase
			auditTypeIndex = i
			break
		}
	}

	// If we found an audit.type field, convert to if_sid
	if auditTypeIndex >= 0 && auditTypeValue != "" {
		if ifSid, exists := auditTypeToIfSid[auditTypeValue]; exists {
			// Set the if_sid
			rule.IfSid = ifSid

			// Remove the audit.type field (no longer needed)
			rule.Fields = append(rule.Fields[:auditTypeIndex], rule.Fields[auditTypeIndex+1:]...)
			return
		}
	}

	// Special case: Handle pcre2 regex patterns for TTY|USER_TTY
	for i, field := range rule.Fields {
		if field.Name == "audit.type" && field.Type == "pcre2" {
			// Check if this is the TTY|USER_TTY pattern
			if strings.Contains(field.Value, "TTY") && strings.Contains(field.Value, "USER_TTY") {
				// Set if_sid to TTY parent rule
				rule.IfSid = "210006"
				// Remove the audit.type field (no longer needed)
				rule.Fields = append(rule.Fields[:i], rule.Fields[i+1:]...)
				return
			}
		}
	}

	// Field-based decoder detection
	hasExecveField := false
	hasPathField := false
	hasSyscallField := false
	hasConfigChangeField := false
	hasTTYField := false

	for _, field := range rule.Fields {
		// Check for EXECVE decoder fields (highest priority for process execution)
		if strings.HasPrefix(field.Name, "audit.execve.") {
			hasExecveField = true
			break // EXECVE is very specific, use it immediately
		}

		// Check for PATH decoder fields (file system operations)
		if strings.HasPrefix(field.Name, "audit.file.") || strings.HasPrefix(field.Name, "audit.directory.") {
			hasPathField = true
		}

		// Check for SYSCALL decoder fields
		if field.Name == "audit.syscall" || field.Name == "audit.arch" ||
			field.Name == "audit.command" || field.Name == "audit.exe" ||
			field.Name == "audit.ppid" || field.Name == "audit.tty" ||
			field.Name == "audit.success" || field.Name == "audit.exit" ||
			field.Name == "audit.key" {
			hasSyscallField = true
		}

		// Check for CONFIG_CHANGE decoder fields
		if field.Name == "audit.op" || field.Name == "audit.list" {
			hasConfigChangeField = true
		}

		// Check for TTY decoder fields (keylogging)
		if field.Name == "audit.data" {
			hasTTYField = true
		}
	}

	// Assign if_sid based on detected decoder (priority order)
	if hasExecveField {
		rule.IfSid = "210001" // auditd-execve
		return
	}
	if hasPathField {
		rule.IfSid = "210002" // auditd-path
		return
	}
	if hasSyscallField {
		rule.IfSid = "210000" // auditd-syscall
		return
	}
	if hasConfigChangeField {
		rule.IfSid = "210003" // auditd-config_change
		return
	}
	if hasTTYField {
		rule.IfSid = "210006" // auditd-tty
		return
	}
}

// optimizeWindowsEventRule converts generic Windows channel parent rules to EventID-specific parent rules
func optimizeWindowsEventRule(rule *types.WazuhRule) {
	// Skip if rule already has if_sid assigned to a specific parent (not generic fallback)
	if rule.IfSid != "" {
		// Check if it's a generic fallback parent (60001, 60002, 60003)
		genericParents := map[string]bool{
			"60001": true, // Security Channel
			"60002": true, // System Channel
			"60003": true, // Application Channel
			"18100": true, // Generic Windows
			"60000": true, // Generic Windows Events
		}

		// If not using generic fallback, this rule is already optimized
		if !genericParents[rule.IfSid] {
			return
		}
	}

	// Map EventID to dedicated parent rule ID
	eventIdToIfSid := map[string]string{
		"4697": "200100", // Security: Service Installation
		"7045": "200101", // System: Service Installation
		"5145": "200102", // Security: Network Share Object Access
		"4624": "200103", // Security: Successful Account Logon
	}

	// Look for win.system.eventID field
	var eventIDValue string
	var eventIDIndex int = -1

	for i, field := range rule.Fields {
		if field.Name == "win.system.eventID" {
			// Found EventID field - extract value (may have (?i)^ prefix and $ suffix for pcre2)
			value := field.Value
			// Remove case-insensitive modifier if present
			value = strings.TrimPrefix(value, "(?i)")
			value = strings.TrimPrefix(value, "^")
			value = strings.TrimSuffix(value, "$")
			// Remove escape characters (e.g., \. becomes .)
			value = strings.ReplaceAll(value, "\\", "")
			eventIDValue = value
			eventIDIndex = i
			break
		}
	}

	// If we found an EventID that has a dedicated parent rule, convert to if_sid
	if eventIDIndex >= 0 && eventIDValue != "" {
		if ifSid, exists := eventIdToIfSid[eventIDValue]; exists {
			// Set the dedicated parent if_sid
			rule.IfSid = ifSid

			// Remove the EventID field since the parent rule already filters by EventID
			rule.Fields = append(rule.Fields[:eventIDIndex], rule.Fields[eventIDIndex+1:]...)
			return
		}
	}
}

// ProcessDnfSets converts DNF (Disjunctive Normal Form) sets into Wazuh rules
func ProcessDnfSets(passingSets [][]string, detections map[string]any, sigmaRule *types.SigmaRule, url string, c *types.Config) {
	for _, set := range passingSets {
		// Filter out boolean placeholders and check if set should be skipped
		filteredSet, shouldSkip := filterBooleanPlaceholders(set)
		if shouldSkip {
			continue
		}

		// Expand selections into detection sets (handles list-of-maps cartesian products)
		detectionSets, selectionNegations := expandDetectionSets(filteredSet, detections)

		// Build and store Wazuh rules for each detection set
		buildAndStoreRules(detectionSets, selectionNegations, sigmaRule, url, c)
	}
}

// filterBooleanPlaceholders removes __TRUE__ and checks for __FALSE__ in DNF sets
func filterBooleanPlaceholders(set []string) ([]string, bool) {
	var filtered []string

	for _, item := range set {
		if item == "__FALSE__" {
			return nil, true // Skip this entire AND group
		}
		if item != "__TRUE__" {
			filtered = append(filtered, item)
		}
	}

	return filtered, false
}

// expandDetectionSets expands detection selections into multiple detection sets
func expandDetectionSets(selections []string, detections map[string]any) ([]map[string]any, map[string]bool) {
	detectionSets := []map[string]any{{}}
	selectionNegations := make(map[string]bool)

	for _, item := range selections {
		// Parse negation
		currentNegate := false
		if strings.HasPrefix(item, "not ") {
			item = strings.TrimPrefix(item, "not ")
			currentNegate = true
		}
		selectionNegations[item] = currentNegate

		val, isList := detections[item].([]any)
		if !isList {
			// Single selection - add to all detection sets
			for _, dSet := range detectionSets {
				dSet[item] = detections[item]
			}
			continue
		}

		// Check if this is a list of maps (OR condition) or list of values
		isListOfMaps := len(val) > 0
		if isListOfMaps {
			if _, ok := val[0].(map[string]any); !ok {
				isListOfMaps = false
			}
		}

		if isListOfMaps {
			// Cartesian product: create separate detection set for each map
			var newDetectionSets []map[string]any
			for _, dSet := range detectionSets {
				for _, listItem := range val {
					newDSet := make(map[string]any)
					for k, v := range dSet {
						newDSet[k] = v
					}
					newDSet[item] = listItem
					newDetectionSets = append(newDetectionSets, newDSet)
				}
			}
			detectionSets = newDetectionSets
		} else {
			// List of values - add to all detection sets as-is (will create regex OR)
			for _, dSet := range detectionSets {
				dSet[item] = detections[item]
			}
		}
	}

	return detectionSets, selectionNegations
}

// buildAndStoreRules creates Wazuh rules from detection sets and stores them by product
func buildAndStoreRules(detectionSets []map[string]any, selectionNegations map[string]bool, sigmaRule *types.SigmaRule, url string, c *types.Config) {
	// Determine which product this rule belongs to
	product := strings.ToLower(sigmaRule.LogSource.Product)
	if product == "" {
		product = "unknown"
	}

	for _, detection := range detectionSets {
		rule := BuildRule(sigmaRule, url, product, c, detection, selectionNegations)
		if rule.ID == "" {
			continue
		}

		// Initialize the product group if it doesn't exist
		if c.Wazuh.XmlRules[product] == nil {
			c.Wazuh.XmlRules[product] = &types.WazuhGroup{
				Name: product + ",",
			}
		}
		c.Wazuh.XmlRules[product].Rules = append(c.Wazuh.XmlRules[product].Rules, rule)
	}
}

// intelligentFieldMapping applies intelligent field mapping for unmapped Sigma fields
// This is particularly useful for Linux auditd where Sigma doesn't specify exact fields
func intelligentFieldMapping(fieldName string, fieldValue string, sigma *types.SigmaRule, c *types.Config) string {
	// Create intelligent mapper with context
	mapper := strategy.IntelligentFieldMapper{
		Config:   c,
		Product:  sigma.LogSource.Product,
		Category: sigma.LogSource.Category,
	}

	// Try to guess the field
	guessedField := mapper.GuessWazuhField(fieldName, fieldValue, sigma)

	if guessedField != "" {
		c.TrackSkips.IntelligentMappings++
		utils.LogIt(utils.INFO, fmt.Sprintf("Intelligent field mapping: %s='%s' → %s (product=%s, category=%s)",
			fieldName, fieldValue, guessedField, sigma.LogSource.Product, sigma.LogSource.Category), nil, c.Info, c.Debug)
	}

	return guessedField
}
