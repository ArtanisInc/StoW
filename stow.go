package main

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Info  bool `yaml:"Info"`
	Debug bool `yaml:"Debug"`
	Sigma struct {
		BaseUrl           string   `yaml:"BaseUrl"`
		ConvertAll        bool     `yaml:"ConvertAll"`
		ConvertCategories []string `yaml:"ConvertCategories"`
		ConvertProducts   []string `yaml:"ConvertProducts"`
		ConvertServices   []string `yaml:"ConvertServices"`
		RuleStatus        []string `yaml:"RuleStatus"`
		RulesRoot         string   `yaml:"RulesRoot"`
		SkipCategories    []string `yaml:"SkipCategories"`
		SkipIds           []string `yaml:"SkipIds"`
		SkipProducts      []string `yaml:"SkipProducts"`
		SkipServices      []string `yaml:"SkipServices"`
	} `yaml:"Sigma"`
	Wazuh struct {
		RulesFile   string `yaml:"RulesFile"`
		RuleIdFile  string `yaml:"RuleIdFile"`
		RuleIdStart int    `yaml:"RuleIdStart"`
		WriteRules  os.File
		Levels      struct {
			Informational int `yaml:"informational"`
			Low           int `yaml:"low"`
			Medium        int `yaml:"medium"`
			High          int `yaml:"high"`
			Critical      int `yaml:"critical"`
		} `yaml:"Levels"`
		Options struct {
			NoFullLog    bool     `yaml:"NoFullLog"`
			SigmaIdEmail []string `yaml:"SigmaIdEmail"`
			EmailAlert   bool     `yaml:"EmailAlert"`
			EmailLevels  []string `yaml:"EmailLevels"`
		} `yaml:"Options"`
		SidGrpMaps struct {
			SigmaIdToWazuhGroup        map[string]string `yaml:"SigmaIdToWazuhGroup"`
			SigmaIdToWazuhId           map[string]string `yaml:"SigmaIdToWazuhId"`
			ProductServiceToWazuhGroup map[string]string `yaml:"ProductServiceToWazuhGroup"`
			ProductServiceToWazuhId    map[string]string `yaml:"ProductServiceToWazuhId"`
		} `yaml:"SidGrpMaps"`
		FieldMaps map[string]map[string]string `yaml:"FieldMaps"`
		XmlRules  map[string]*WazuhGroup
	} `yaml:"Wazuh"`
	// OR logic can force the creation of multiple Wazuh rules
	// Because of this we need to track Sigma to Wazuh rule ids between runs
	Ids struct {
		PreviousUsed []int            `yaml:"PreviousUsed"`
		CurrentUsed  []int            `yaml:"CurrentUsed"`
		SigmaToWazuh map[string][]int `yaml:"SigmaToWazuh"`
	}
	TrackSkips struct {
		NearSkips         int
		Cidr              int
		ParenSkips        int
		TimeframeSkips    int
		ExperimentalSkips int
		HardSkipped       int
		RulesSkipped      int
		ErrorCount        int
		FieldTooLong      int
		ConvertedToCDB    int
	}
	CDBLists map[string][]string // map[listName]values
}

func (c *Config) getSigmaRules(path string, f os.FileInfo, err error) error {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
	if !f.IsDir() && strings.HasSuffix(path, ".yml") {
		ReadYamlFile(path, c)
	}
	return nil
}

func initPreviousUsed(c *Config) {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
	for _, ids := range c.Ids.SigmaToWazuh {
		c.Ids.PreviousUsed = append(c.Ids.PreviousUsed, ids...)
	}
}

func LoadStowConfig(c *Config) {
	// Load Sigma and Wazuh config for rule processing
	data, err := os.ReadFile("./config.yaml")
	if err != nil {
		LogIt(ERROR, "", err, c.Info, c.Debug)
	}
	err = yaml.Unmarshal(data, &c)
	if err != nil {
		LogIt(ERROR, "", err, c.Info, c.Debug)
	}

	// Lowercase the FieldMaps keys for case-insensitive matching
	lowerFieldMaps := make(map[string]map[string]string)
	for product, fields := range c.Wazuh.FieldMaps {
		lowerFieldMaps[strings.ToLower(product)] = fields
	}
	c.Wazuh.FieldMaps = lowerFieldMaps
}

func LoadSigmaWazuhIdMap(c *Config) {
	// Load Sigma ID to Wazuh ID mappings
	data, err := os.ReadFile(c.Wazuh.RuleIdFile)
	if err != nil {
		LogIt(WARN, "Could not read rule_id_file, creating a new one", err, c.Info, c.Debug)
		file, err := os.Create(c.Wazuh.RuleIdFile)
		if err != nil {
			LogIt(ERROR, "", err, c.Info, c.Debug)
			return
		}
		file.Close()
		data = nil
	}
	err = yaml.Unmarshal(data, &c.Ids.SigmaToWazuh)
	if err != nil {
		LogIt(ERROR, "", err, c.Info, c.Debug)
		data = nil
	}
}

func InitConfig() *Config {
	c := &Config{
		Ids: struct {
			PreviousUsed []int            `yaml:"PreviousUsed"`
			CurrentUsed  []int            `yaml:"CurrentUsed"`
			SigmaToWazuh map[string][]int `yaml:"SigmaToWazuh"`
		}{
			SigmaToWazuh: make(map[string][]int),
		},
	}

	LoadStowConfig(c)
	LoadSigmaWazuhIdMap(c)

	initPreviousUsed(c)
	LogIt(DEBUG, "", nil, c.Info, c.Debug)

	return c
}

type SigmaRule struct {
	Title       string   `yaml:"title"`
	ID          string   `yaml:"id"`
	Status      string   `yaml:"status"`
	Description string   `yaml:"description"`
	References  []string `yaml:"references"`
	Author      string   `yaml:"author"`
	Date        string   `yaml:"date"`
	Modified    string   `yaml:"modified"`
	Tags        []string `yaml:"tags"`
	LogSource   struct {
		Product  string `yaml:"product"`
		Service  string `yaml:"service"`
		Category string `yaml:"category"`
	} `yaml:"logsource"`
	Detection      any      `yaml:"detection"`
	FalsePositives []string `yaml:"falsepositives"`
	Level          string   `yaml:"level"`
}

// outer rules xml
type WazuhGroup struct {
	XMLName xml.Name    `xml:"group"`
	Name    string      `xml:"name,attr"`
	Header  xml.Comment `xml:",comment"`
	Rules   []WazuhRule `xml:"rule"`
}

type Field struct {
	Name   string `xml:"name,attr"`
	Negate string `xml:"negate,attr,omitempty"`
	Type   string `xml:"type,attr"`
	Value  string `xml:",chardata"`
}

// IPField represents srcip or dstip elements with optional negation
type IPField struct {
	Negate string `xml:"negate,attr,omitempty"`
	Value  string `xml:",chardata"`
}

// ListField represents a list lookup field
type ListField struct {
	Field  string `xml:"field,attr"`
	Lookup string `xml:"lookup,attr"`
	Negate string `xml:"negate,attr,omitempty"`
	Value  string `xml:",chardata"` // Path to CDB list file
}

// RuleFields contains all field types that can be extracted from Sigma rules
type RuleFields struct {
	Fields    []Field
	SrcIps    []IPField
	DstIps    []IPField
	ListFields []ListField
}

// per rule xml
type WazuhRule struct {
	XMLName xml.Name `xml:"rule"`
	ID      string   `xml:"id,attr"`
	Level   string   `xml:"level,attr"`
	Info    struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"info,omitempty"`
	Author           xml.Comment `xml:",comment"`
	SigmaDescription xml.Comment `xml:",comment"`
	Date             xml.Comment `xml:",comment"`
	Modified         xml.Comment `xml:",comment"`
	Status           xml.Comment `xml:",comment"`
	SigmaID          xml.Comment `xml:",comment"`
	Mitre            struct {
		IDs []string `xml:"id,omitempty"`
	} `xml:"mitre,omitempty"`
	Description string      `xml:"description"`
	Options     []string    `xml:"options,omitempty"`
	Groups      string      `xml:"group,omitempty"`
	IfSid       string      `xml:"if_sid,omitempty"`
	IfGroup     string      `xml:"if_group,omitempty"`
	SrcIps      []IPField   `xml:"srcip,omitempty"`
	DstIps      []IPField   `xml:"dstip,omitempty"`
	Lists       []ListField `xml:"list,omitempty"`
	Fields      []Field     `xml:"field"`
}

type Stack []int

func (s *Stack) Push(v int) {
	*s = append(*s, v)
}

func (s *Stack) Pop() int {
	res := (*s)[len(*s)-1]
	*s = (*s)[:len(*s)-1]
	return res
}

func HandleB64OffsetsList(value []string) string {
	offset1 := strings.Join(EncodeList(value, ""), "|")
	offset2 := strings.Join(EncodeList(value, " "), "|")[2:]
	offset3 := strings.Join(EncodeList(value, "  "), "|")[3:]
	return offset1 + "|" + offset2 + "|" + offset3
}

func EncodeList(value []string, prefix string) []string {
	encoded := make([]string, len(value))
	for i, v := range value {
		encoded[i] = base64.StdEncoding.EncodeToString([]byte(prefix + v))
	}
	return encoded
}

func HandleB64Offsets(value string) string {
	offset1 := base64.StdEncoding.EncodeToString([]byte(value))
	offset2 := base64.StdEncoding.EncodeToString([]byte(" " + value))[2:]
	offset3 := base64.StdEncoding.EncodeToString([]byte("  " + value))[3:]
	return offset1 + "|" + offset2 + "|" + offset3
}

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

func AddToMapStrToInts(c *Config, sigmaId string, wazuhId int) {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
	// If the key doesn't exist, add it to the map with a new slice
	if _, ok := c.Ids.SigmaToWazuh[sigmaId]; !ok {
		c.Ids.SigmaToWazuh[sigmaId] = []int{wazuhId}
		return
	}
	// If the key exists, append to the slice
	c.Ids.SigmaToWazuh[sigmaId] = append(c.Ids.SigmaToWazuh[sigmaId], wazuhId)
}

func TrackIdMaps(sigmaId string, c *Config) string {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
	// has this Sigma rule been converted previously, reuse its Wazuh rule IDs
	if ids, ok := c.Ids.SigmaToWazuh[sigmaId]; ok {
		for _, id := range ids {
			if !slices.Contains(c.Ids.CurrentUsed, id) {
				c.Ids.CurrentUsed = append(c.Ids.CurrentUsed, id)
				return strconv.Itoa(id)
			}
		}
	}
	// new Sigma rule, find an unused Wazuh rule ID
	for slices.Contains(c.Ids.PreviousUsed, c.Wazuh.RuleIdStart) ||
		slices.Contains(c.Ids.CurrentUsed, c.Wazuh.RuleIdStart) {
		c.Wazuh.RuleIdStart++
	}
	AddToMapStrToInts(c, sigmaId, c.Wazuh.RuleIdStart)
	c.Ids.CurrentUsed = append(c.Ids.CurrentUsed, c.Wazuh.RuleIdStart)
	return strconv.Itoa(c.Wazuh.RuleIdStart)
}

func GetLevel(sigmaLevel string, c *Config) int {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
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

func GetIfGrpSid(sigma *SigmaRule, c *Config) (string, string) {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
	// Get Wazuh if_group or if_sids dependencies for converted rules
	switch {
	case c.Wazuh.SidGrpMaps.SigmaIdToWazuhGroup[sigma.ID] != "":
		return "grp", c.Wazuh.SidGrpMaps.SigmaIdToWazuhGroup[sigma.ID]
	case c.Wazuh.SidGrpMaps.SigmaIdToWazuhId[sigma.ID] != "":
		return "sid", c.Wazuh.SidGrpMaps.SigmaIdToWazuhId[sigma.ID]
	case c.Wazuh.SidGrpMaps.ProductServiceToWazuhGroup[sigma.LogSource.Service] != "":
		return "grp", c.Wazuh.SidGrpMaps.ProductServiceToWazuhGroup[sigma.LogSource.Service]
	case c.Wazuh.SidGrpMaps.ProductServiceToWazuhGroup[sigma.LogSource.Product] != "":
		return "grp", c.Wazuh.SidGrpMaps.ProductServiceToWazuhGroup[sigma.LogSource.Product]
	case c.Wazuh.SidGrpMaps.ProductServiceToWazuhId[sigma.LogSource.Service] != "":
		return "sid", c.Wazuh.SidGrpMaps.ProductServiceToWazuhId[sigma.LogSource.Service]
	case c.Wazuh.SidGrpMaps.ProductServiceToWazuhId[sigma.LogSource.Product] != "":
		return "sid", c.Wazuh.SidGrpMaps.ProductServiceToWazuhId[sigma.LogSource.Product]
	default:
		return "sid", ""
	}
}

func GetGroups(sigma *SigmaRule, c *Config) string {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
	var groups string
	if sigma.LogSource.Category != "" {
		groups = sigma.LogSource.Category + ","
	}
	if sigma.LogSource.Product != "" {
		groups += sigma.LogSource.Product + ","
	}
	if sigma.LogSource.Service != "" {
		groups += sigma.LogSource.Service + ","
	}
	return groups
}

func GetOptions(sigma *SigmaRule, c *Config) []string {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
	var options []string
	if c.Wazuh.Options.NoFullLog {
		options = append(options, "no_full_log")

	}
	if c.Wazuh.Options.EmailAlert &&
		(slices.Contains(c.Wazuh.Options.SigmaIdEmail, sigma.ID) ||
			slices.Contains(c.Wazuh.Options.EmailLevels, sigma.Level)) {
		options = append(options, "alert_by_email")
	}
	return options
}

func GetWazuhField(fieldName string, sigma *SigmaRule, c *Config) string {
	if f, ok := c.Wazuh.FieldMaps[strings.ToLower(sigma.LogSource.Product)][fieldName]; ok {
		return f
	} else {
		return "full_log"
	}
}

func GetFieldValues(value any, fieldName string, c *Config) []string {
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
		LogIt(DEBUG, fmt.Sprintf("Unsupported value type for field '%s': %T", fieldName, v), nil, c.Info, c.Debug)
	}

	if len(values) == 0 {
		LogIt(DEBUG, fmt.Sprintf("No values extracted for field '%s'", fieldName), nil, c.Info, c.Debug)
	}
	return values
}

// processDetectionField extracts and processes a single field from a Sigma detection.
func processDetectionField(selectionKey string, key string, value any, sigma *SigmaRule, c *Config, fields *[]Field, srcIps *[]IPField, dstIps *[]IPField, selectionNegations map[string]bool) {
	LogIt(INFO, fmt.Sprintf("processDetectionField key: %s, value: %v", key, value), nil, c.Info, c.Debug)
	// Handle modifiers in the key
	parts := strings.Split(key, "|")
	fieldName := parts[0]

	wazuhField := GetWazuhField(fieldName, sigma, c)

	field := Field{
		Name: wazuhField,
		Type: "pcre2",
	}

	// Apply negation if this selectionKey is marked as negated
	if selectionNegations[selectionKey] {
		field.Negate = "yes"
	}

	var values []string
	isRegex := false
	isB64 := false
	isCIDR := false
	startsWith := false
	endsWith := false

	if len(parts) > 1 {
		for _, modifier := range parts[1:] {
			switch strings.ToLower(modifier) {
			case "contains":
				// Default behavior, no special handling needed
			case "startswith":
				startsWith = true
			case "endswith":
				endsWith = true
			case "all":
				// Will be handled later
			case "re":
				isRegex = true
			case "base64offset":
				isB64 = true
			case "base64":
				isB64 = true
			case "windash":
				value = HandleWindash(value)
			case "cidr":
				isCIDR = true
			}
		}
	}

	// Handle CIDR modifier for IP fields
	if isCIDR {
		values = GetFieldValues(value, fieldName, c)

		// Determine if this is a source or destination IP field
		lowerFieldName := strings.ToLower(fieldName)
		isSrcIP := strings.Contains(lowerFieldName, "sourceip") ||
				   strings.Contains(lowerFieldName, "src_ip") ||
				   strings.Contains(lowerFieldName, "srcip") ||
				   strings.Contains(lowerFieldName, "clientip") ||
				   strings.Contains(lowerFieldName, "clientaddress") ||
				   lowerFieldName == "c-ip"
		isDstIP := strings.Contains(lowerFieldName, "destinationip") ||
				   strings.Contains(lowerFieldName, "dst_ip") ||
				   strings.Contains(lowerFieldName, "dstip") ||
				   strings.Contains(lowerFieldName, "destination")

		// If not clearly source or destination, treat as generic IP (use as srcip)
		isIP := strings.Contains(lowerFieldName, "ipaddress") ||
				strings.Contains(lowerFieldName, "ip_address") ||
				lowerFieldName == "ipaddress" ||
				strings.Contains(lowerFieldName, "address") && strings.Contains(lowerFieldName, "ip")

		// Create IP fields with CIDR notation
		negate := ""
		if selectionNegations[selectionKey] {
			negate = "yes"
		}

		for _, v := range values {
			ipField := IPField{
				Negate: negate,
				Value:  v,
			}

			if isSrcIP {
				*srcIps = append(*srcIps, ipField)
				LogIt(INFO, fmt.Sprintf("Added srcip CIDR field: %s (negate=%s)", v, negate), nil, c.Info, c.Debug)
			} else if isDstIP {
				*dstIps = append(*dstIps, ipField)
				LogIt(INFO, fmt.Sprintf("Added dstip CIDR field: %s (negate=%s)", v, negate), nil, c.Info, c.Debug)
			} else if isIP {
				// Generic IP field - default to srcip
				*srcIps = append(*srcIps, ipField)
				LogIt(INFO, fmt.Sprintf("Added srcip CIDR field (generic IP): %s (negate=%s)", v, negate), nil, c.Info, c.Debug)
			} else {
				// If we can't determine IP direction, log a warning and skip
				LogIt(WARN, fmt.Sprintf("CIDR modifier used on non-IP field: %s", fieldName), nil, c.Info, c.Debug)
			}
		}
		return // Early return for CIDR fields
	}

	values = GetFieldValues(value, fieldName, c)

	var fieldValues []string
	if slices.Contains(parts, "all") {
		for _, v := range values {
			newField := field
			if isB64 {
				newField.Value = HandleB64Offsets(v)
			} else if isRegex {
				newField.Value = v
			} else if startsWith || endsWith {
				prefix := ""
				suffix := ""
				if startsWith {
					prefix = "^"
				}
				if endsWith {
					suffix = "$"
				}
				newField.Value = "(?i)" + prefix + regexp.QuoteMeta(v) + suffix
			} else {
				newField.Value = "(?i)" + regexp.QuoteMeta(v)
			}
			*fields = append(*fields, newField) // Append to the passed slice pointer
			LogIt(INFO, fmt.Sprintf("processDetectionField appended field: %v", newField), nil, c.Info, c.Debug)
		}
		return // Return from helper function
	}

	for _, v := range values {
		if isB64 {
			fieldValues = append(fieldValues, HandleB64Offsets(v))
		} else if isRegex {
			fieldValues = append(fieldValues, v)
		} else {
			fieldValues = append(fieldValues, regexp.QuoteMeta(v))
		}
	}

	if len(fieldValues) == 0 {
		LogIt(DEBUG, fmt.Sprintf("No processed fieldValues for field '%s'", fieldName), nil, c.Info, c.Debug)
	}

	if len(fieldValues) > 0 {
		if isRegex {
			field.Value = strings.Join(fieldValues, "|")
		} else {
			value := strings.Join(fieldValues, "|")
			if len(fieldValues) > 1 {
				value = "(?:" + value + ")"
			}
			if startsWith {
				value = "^" + value
			}
			if endsWith {
				value = value + "$"
			}
			field.Value = "(?i)" + value
		}
		*fields = append(*fields, field) // Append to the passed slice pointer
		LogIt(INFO, fmt.Sprintf("processDetectionField appended field: %v", field), nil, c.Info, c.Debug)
	}
}

func GetFields(detection map[string]any, sigma *SigmaRule, c *Config, selectionNegations map[string]bool) RuleFields {
	LogIt(INFO, fmt.Sprintf("GetFields detection: %v", detection), nil, c.Info, c.Debug)
	var fields []Field
	var srcIps []IPField
	var dstIps []IPField

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
	LogIt(INFO, fmt.Sprintf("GetFields fields: %v, srcIps: %v, dstIps: %v", fields, srcIps, dstIps), nil, c.Info, c.Debug)
	return RuleFields{
		Fields: fields,
		SrcIps: srcIps,
		DstIps: dstIps,
	}
}

// sanitizeFieldName removes special characters from field names for use in filenames
func sanitizeFieldName(fieldName string) string {
	// Replace dots and other special characters with underscores
	fieldName = strings.ReplaceAll(fieldName, ".", "_")
	fieldName = strings.ReplaceAll(fieldName, "/", "_")
	fieldName = strings.ReplaceAll(fieldName, "\\", "_")
	fieldName = strings.ReplaceAll(fieldName, " ", "_")
	return fieldName
}

// extractValuesFromRegex extracts individual values from an OR regex pattern
// Pattern format: (?i)(?:value1|value2|value3)
func extractValuesFromRegex(regexPattern string) []string {
	var values []string

	// Remove case-insensitive flag: (?i)
	regexPattern = strings.Replace(regexPattern, "(?i)", "", 1)

	// Remove non-capturing group: (?:...)
	regexPattern = strings.TrimPrefix(regexPattern, "(?:")
	regexPattern = strings.TrimSuffix(regexPattern, ")")

	// Handle escaped pipes (not separators)
	// Replace escaped pipes temporarily
	regexPattern = strings.ReplaceAll(regexPattern, "\\|", "<<<PIPE>>>")

	// Split by unescaped pipes
	parts := strings.Split(regexPattern, "|")

	for _, part := range parts {
		// Restore escaped pipes
		part = strings.ReplaceAll(part, "<<<PIPE>>>", "|")
		part = strings.TrimSpace(part)

		// Remove regex escaping for CDB list (keep the raw value)
		// This is safe for CDB lists as they use exact matching
		part = strings.ReplaceAll(part, "\\.", ".")
		part = strings.ReplaceAll(part, "\\\\", "\\")

		if part != "" {
			values = append(values, part)
		}
	}

	return values
}

func BuildRule(sigma *SigmaRule, url string, c *Config, detections map[string]any, selectionNegations map[string]bool) WazuhRule {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
	var rule WazuhRule

	ruleFields := GetFields(detections, sigma, c, selectionNegations)
	if len(ruleFields.Fields) == 0 && len(ruleFields.SrcIps) == 0 && len(ruleFields.DstIps) == 0 {
		LogIt(WARN, "No fields found for rule: "+sigma.ID+" URL: "+url, nil, c.Info, c.Debug)
		return WazuhRule{}
	}

	// Check for field values that exceed Wazuh's limits (max ~4096 characters)
	// Convert them to CDB lists instead of skipping
	const maxFieldLength = 4096
	var finalFields []Field
	var listFields []ListField

	for i, field := range ruleFields.Fields {
		if len(field.Value) > maxFieldLength {
			// Extract values from the regex pattern
			values := extractValuesFromRegex(field.Value)

			if len(values) == 0 {
				LogIt(WARN, fmt.Sprintf("Rule %s has field value exceeding limit but couldn't extract values. Skipping rule.", sigma.ID), nil, c.Info, c.Debug)
				c.TrackSkips.FieldTooLong++
				c.TrackSkips.RulesSkipped++
				return WazuhRule{}
			}

			// Create a CDB list name using Sigma ID
			listName := fmt.Sprintf("sigma_%s_%d_%s", strings.ReplaceAll(sigma.ID, "-", ""), i, sanitizeFieldName(field.Name))

			// Store the values for later CDB generation
			c.CDBLists[listName] = values

			// Create a list field instead of regular field
			listField := ListField{
				Field:  field.Name,
				Lookup: "match_key",
				Negate: field.Negate,
				Value:  fmt.Sprintf("etc/lists/%s", listName),
			}
			listFields = append(listFields, listField)

			LogIt(INFO, fmt.Sprintf("Rule %s field '%s' converted to CDB list with %d values (%d chars → CDB)", sigma.ID, field.Name, len(values), len(field.Value)), nil, c.Info, c.Debug)
			c.TrackSkips.ConvertedToCDB++
		} else {
			finalFields = append(finalFields, field)
		}
	}

	// Update ruleFields with the processed fields
	ruleFields.Fields = finalFields
	ruleFields.ListFields = listFields

	rule.ID = TrackIdMaps(sigma.ID, c)
	rule.Level = strconv.Itoa(GetLevel(sigma.Level, c))
	rule.Description = sigma.Title
	rule.Info.Type = "link"
	rule.Info.Value = url
	// sometimes we see "--" in sigma fields which will break xml when in comments
	rule.Author = xml.Comment("     Author: " + strings.Replace(sigma.Author, "--", "-", -1))
	rule.SigmaDescription = xml.Comment("Description: " + strings.Replace(sigma.Description, "--", "-", -1))
	rule.Date = xml.Comment("    Created: " + strings.Replace(sigma.Date, "--", "-", -1))
	rule.Modified = xml.Comment("   Modified: " + strings.Replace(sigma.Modified, "--", "-", -1))
	rule.Status = xml.Comment("     Status: " + strings.Replace(sigma.Status, "--", "-", -1))
	rule.SigmaID = xml.Comment("   Sigma ID: " + strings.Replace(sigma.ID, "--", "-", -1))
	rule.Mitre.IDs = sigma.Tags
	rule.Options = GetOptions(sigma, c)
	rule.Groups = GetGroups(sigma, c)
	ifType, value := GetIfGrpSid(sigma, c)
	if ifType == "grp" {
		rule.IfGroup = value
	} else {
		rule.IfSid = value
	}

	rule.Fields = ruleFields.Fields
	rule.SrcIps = ruleFields.SrcIps
	rule.DstIps = ruleFields.DstIps
	rule.Lists = ruleFields.ListFields

	return rule
}

func SkipSigmaRule(sigma *SigmaRule, c *Config) bool {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)

	// Check if rule is explicitly skipped
	if slices.Contains(c.Sigma.SkipIds, strings.ToLower(sigma.ID)) {
		LogIt(INFO, "Skip Sigma rule ID: "+sigma.ID, nil, c.Info, c.Debug)
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
		LogIt(INFO, "Skip Sigma rule status: "+sigma.ID, nil, c.Info, c.Debug)
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
	LogIt(INFO, "Skip Sigma rule default: "+sigma.ID, nil, c.Info, c.Debug)
	c.TrackSkips.RulesSkipped++
	return true
}

func GetTopLevelLogicCondition(sigma SigmaRule, c *Config) map[string]any {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
	detections := make(map[string]any)
	v := reflect.ValueOf(sigma.Detection)
	for _, k := range v.MapKeys() {
		value := v.MapIndex(k)
		key := k.Interface().(string)
		detections[key] = value.Interface()
	}
	return detections
}

func PrintValues(detections map[string]any) {
	for k, v := range detections {
		fmt.Printf("%v - %v\n", k, v)
	}
}

type Token struct {
	Type  string
	Value string
}

func tokenize(expr string) []Token {
	tokens := []Token{}
	words := strings.Fields(expr)
	for i := 0; i < len(words); i++ {
		word := strings.ToLower(words[i])
		switch word {
		case "(":
			tokens = append(tokens, Token{"LPAREN", "("})
		case ")":
			tokens = append(tokens, Token{"RPAREN", ")"})
		case "and":
			tokens = append(tokens, Token{"AND", "and"})
		case "or":
			tokens = append(tokens, Token{"OR", "or"})
		case "not":
			tokens = append(tokens, Token{"NOT", "not"})
		case "1_of":
			tokens = append(tokens, Token{"ONEOF", "1_of"})
		case "all_of":
			tokens = append(tokens, Token{"ALLOF", "all_of"})
		default:
			tokens = append(tokens, Token{"LITERAL", words[i]})
		}
	}
	return tokens
}

func parse(tokens []Token) [][]string {
	if len(tokens) == 0 {
		return [][]string{{""}}
	}

	// Infix to postfix conversion
	var postfix []Token
	var stack []Token
	precedence := map[string]int{"or": 1, "and": 2, "not": 3}

	for _, token := range tokens {
		switch token.Type {
		case "LITERAL":
			postfix = append(postfix, token)
		case "LPAREN":
			stack = append(stack, token)
		case "RPAREN":
			for len(stack) > 0 && stack[len(stack)-1].Type != "LPAREN" {
				postfix = append(postfix, stack[len(stack)-1])
				stack = stack[:len(stack)-1]
			}
			if len(stack) > 0 {
				stack = stack[:len(stack)-1] // Pop LPAREN
			}
		default: // Operator
			for len(stack) > 0 && stack[len(stack)-1].Type != "LPAREN" && precedence[token.Value] <= precedence[stack[len(stack)-1].Value] {
				postfix = append(postfix, stack[len(stack)-1])
				stack = stack[:len(stack)-1]
			}
			stack = append(stack, token)
		}
	}

	for len(stack) > 0 {
		postfix = append(postfix, stack[len(stack)-1])
		stack = stack[:len(stack)-1]
	}

	// Evaluate postfix expression
	var evalStack [][][]string
	for _, token := range postfix {
		switch token.Type {
		case "LITERAL":
			evalStack = append(evalStack, [][]string{{token.Value}})
		case "NOT":
			if len(evalStack) < 1 {
				return [][]string{}
			}
			op := evalStack[len(evalStack)-1]
			evalStack = evalStack[:len(evalStack)-1]
			var negated [][]string
			for _, set := range op {
				var newSet []string
				for _, item := range set {
					newSet = append(newSet, "not "+item)
				}
				negated = append(negated, newSet)
			}
			evalStack = append(evalStack, negated)
		case "AND":
			if len(evalStack) < 2 {
				return [][]string{}
			}
			op2 := evalStack[len(evalStack)-1]
			evalStack = evalStack[:len(evalStack)-1]
			op1 := evalStack[len(evalStack)-1]
			evalStack = evalStack[:len(evalStack)-1]
			var andResult [][]string
			for _, s1 := range op1 {
				for _, s2 := range op2 {
					andResult = append(andResult, append(s1, s2...))
				}
			}
			evalStack = append(evalStack, andResult)
		case "OR":
			if len(evalStack) < 2 {
				return [][]string{}
			}
			op2 := evalStack[len(evalStack)-1]
			evalStack = evalStack[:len(evalStack)-1]
			op1 := evalStack[len(evalStack)-1]
			evalStack = evalStack[:len(evalStack)-1]
			evalStack = append(evalStack, append(op1, op2...))
		}
	}

	if len(evalStack) == 0 {
		return [][]string{}
	}
	return evalStack[0]
}

// Create tokens out of Sigma condition for better logic parsing
func fixupCondition(condition string) string {
	condition = strings.Replace(condition, "1 of them", "1_of them", -1)
	condition = strings.Replace(condition, "all of them", "all_of them", -1)
	condition = strings.Replace(condition, "1 of", "1_of", -1)
	condition = strings.Replace(condition, "all of", "all_of", -1)
	condition = strings.Replace(condition, "(", " ( ", -1)
	condition = strings.Replace(condition, ")", " ) ", -1)
	return condition
}

func convertToDNF(expr string) [][]string {
	tokens := tokenize(expr)
	return parse(tokens)
}

func PreprocessCondition(condition string, detections map[string]any, c *Config) string {
	LogIt(INFO, fmt.Sprintf("Original condition: %s", condition), nil, c.Info, c.Debug)
	// Pre-process condition to expand '1_of' and 'all_of'
	re := regexp.MustCompile(`(not\s+)?(1_of|all_of)\s+(them|[a-zA-Z0-9_\*]+)`)
	matches := re.FindAllStringSubmatch(condition, -1)

	for _, match := range matches {
		LogIt(INFO, fmt.Sprintf("Found match: %v", match), nil, c.Info, c.Debug)
		isNot := match[1] != ""
		directive := match[2]
		pattern := match[3]
		LogIt(INFO, fmt.Sprintf("Pattern: %s", pattern), nil, c.Info, c.Debug)

		var matchingSelections []string
		wildcard := strings.HasSuffix(pattern, "*")
		prefix := strings.TrimSuffix(pattern, "*")

		if pattern == "them" {
			for d := range detections {
				if d != "condition" {
					matchingSelections = append(matchingSelections, d)
				}
			}
		} else {
			for d := range detections {
				if d == "condition" {
					continue
				}
				if wildcard && strings.HasPrefix(d, prefix) {
					matchingSelections = append(matchingSelections, d)
				} else if d == pattern {
					matchingSelections = append(matchingSelections, d)
				}
			}
		}
		LogIt(INFO, fmt.Sprintf("Matching selections: %v", matchingSelections), nil, c.Info, c.Debug)

		if len(matchingSelections) > 0 {
			var replacement string
			if directive == "1_of" {
				if isNot {
					var negatedSelections []string
					for _, s := range matchingSelections {
						negatedSelections = append(negatedSelections, "not "+s)
					}
					replacement = " ( " + strings.Join(negatedSelections, " and ") + " ) "
				} else {
					replacement = " ( " + strings.Join(matchingSelections, " or ") + " ) "
				}
			} else { // all_of
				if isNot {
					var negatedSelections []string
					for _, s := range matchingSelections {
						negatedSelections = append(negatedSelections, "not "+s)
					}
					replacement = " ( " + strings.Join(negatedSelections, " or ") + " ) "
				} else {
					replacement = " ( " + strings.Join(matchingSelections, " and ") + " ) "
				}
			}
			condition = strings.Replace(condition, match[0], replacement, 1)
			LogIt(INFO, fmt.Sprintf("New condition: %s", condition), nil, c.Info, c.Debug)
		} else {
			var replacement string
			if directive == "1_of" {
				if isNot {
					replacement = "__TRUE__" // not (FALSE) is TRUE
				} else {
					replacement = "__FALSE__"
				}
			} else { // all_of
				if isNot {
					replacement = "__FALSE__" // not (TRUE) is FALSE
				} else {
					replacement = "__TRUE__"
				}
			}
			condition = strings.Replace(condition, match[0], replacement, 1)
			LogIt(INFO, fmt.Sprintf("New condition: %s", condition), nil, c.Info, c.Debug)
		}
	}
	return condition
}

func ProcessDnfSets(passingSets [][]string, detections map[string]any, sigmaRule *SigmaRule, url string, c *Config) {
	for _, set := range passingSets { // Each 'set' is an AND group of selection names
		isFalse := false
		var newSet []string
		for _, item := range set {
			if item == "__FALSE__" {
				isFalse = true
				break
			}
			if item != "__TRUE__" {
				newSet = append(newSet, item)
			}
		}

		if isFalse {
			continue // This whole AND group is false
		}

		// Each 'set' from the DNF represents a potential Wazuh rule (a conjunction of conditions).
		// However, a selection within that set can be a list of maps, which is an OR that requires
		// expanding into multiple rules.
		// detectionSets will hold all the possible detection maps after expanding any lists of maps.
		detectionSets := []map[string]any{{}}
		selectionNegations := make(map[string]bool)

		for _, item := range newSet {
			currentNegate := false
			if strings.HasPrefix(item, "not ") {
				item = strings.TrimPrefix(item, "not ")
				currentNegate = true
			}
			selectionNegations[item] = currentNegate

			if val, isList := detections[item].([]any); isList {
				isListOfMaps := false
				if len(val) > 0 {
					// Check if the first element is a map to determine the type of list
					if _, ok := val[0].(map[string]any); ok {
						isListOfMaps = true
					}
				}

				if isListOfMaps {
					// This selection is a list of maps. This is an OR condition between the map items.
					// We need to create a new Wazuh rule for each map in the list.
					// We do this by creating a cartesian product of the existing detectionSets
					// and the new list of maps.
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
					// This is a list of values (strings/ints). Treat it as a single selection
					// that will be handled by processDetectionField to create a regex OR.
					for _, dSet := range detectionSets {
						dSet[item] = detections[item]
					}
				}
			} else {
				// This is a single selection, not a list. Add it to all detection sets.
				for _, dSet := range detectionSets {
					dSet[item] = detections[item]
				}
			}
		}

		for _, detection := range detectionSets {
			rule := BuildRule(sigmaRule, url, c, detection, selectionNegations)
			if rule.ID != "" {
				// Determine which product this rule belongs to
				product := strings.ToLower(sigmaRule.LogSource.Product)
				if product == "" {
					product = "unknown"
				}
				// Initialize the product group if it doesn't exist
				if c.Wazuh.XmlRules[product] == nil {
					c.Wazuh.XmlRules[product] = &WazuhGroup{
						Name: product + ",",
					}
				}
				c.Wazuh.XmlRules[product].Rules = append(c.Wazuh.XmlRules[product].Rules, rule)
			}
		}
	}
}

func ReadYamlFile(path string, c *Config) {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
	data, err := os.ReadFile(path)
	if err != nil {
		LogIt(ERROR, "", err, c.Info, c.Debug)
		return
	}
	LogIt(INFO, path, nil, c.Info, c.Debug)
	relPath, err := filepath.Rel(c.Sigma.RulesRoot, path)
	if err != nil {
		LogIt(ERROR, "", err, c.Info, c.Debug)
		relPath = path
	}
	url := c.Sigma.BaseUrl + "/" + filepath.ToSlash(relPath)

	var sigmaRule SigmaRule

	err = yaml.Unmarshal(data, &sigmaRule)
	if err != nil {
		LogIt(ERROR, "", err, c.Info, c.Debug)
		return
	}

	if SkipSigmaRule(&sigmaRule, c) {
		return
	}

	detectionBytes, _ := yaml.Marshal(sigmaRule.Detection)
	detectionString := string(detectionBytes)

	if strings.Contains(detectionString, "timeframe:") {
		LogIt(INFO, "Skip Sigma rule timeframe: "+sigmaRule.ID, nil, c.Info, c.Debug)
		c.TrackSkips.TimeframeSkips++
		c.TrackSkips.RulesSkipped++
		return
	}
	// CIDR modifier is now supported, no need to skip
	// Removed skip check for |cidr: modifier

	detections := GetTopLevelLogicCondition(sigmaRule, c)
	condition, ok := detections["condition"].(string)
	if !ok {
		LogIt(ERROR, "condition is not a string", nil, c.Info, c.Debug)
		return
	}
	condition = fixupCondition(condition)

	condition = PreprocessCondition(condition, detections, c)

	passingSets := convertToDNF(condition)

	ProcessDnfSets(passingSets, detections, &sigmaRule, url, c)
}

func WriteWazuhXmlRules(c *Config) {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)

	// Iterate through each product and write separate XML files
	for product, xmlRules := range c.Wazuh.XmlRules {
		if len(xmlRules.Rules) == 0 {
			continue // Skip empty rule sets
		}

		// Create filename based on product
		filename := fmt.Sprintf("sigma_%s.xml", product)

		// Create the file
		file, err := os.Create(filename)
		if err != nil {
			LogIt(ERROR, fmt.Sprintf("Failed to create file %s", filename), err, c.Info, c.Debug)
			continue
		}

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
			LogIt(ERROR, fmt.Sprintf("Failed to encode rules for %s", product), err, c.Info, c.Debug)
		}
		if _, err := file.WriteString("\n"); err != nil {
			LogIt(ERROR, "", err, c.Info, c.Debug)
		}

		if err := file.Close(); err != nil {
			LogIt(ERROR, fmt.Sprintf("Failed to close file %s", filename), err, c.Info, c.Debug)
		}
		fmt.Printf("Created %s with %d rules\n", filename, len(xmlRules.Rules))
	}
}

func WriteCDBLists(c *Config) {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)

	if len(c.CDBLists) == 0 {
		return
	}

	// Create lists directory if it doesn't exist
	listsDir := "lists"
	if err := os.MkdirAll(listsDir, 0755); err != nil {
		LogIt(ERROR, fmt.Sprintf("Failed to create lists directory: %s", listsDir), err, c.Info, c.Debug)
		return
	}

	totalEntries := 0
	// Write each CDB list file
	for listName, values := range c.CDBLists {
		filename := filepath.Join(listsDir, listName)

		// Create the list file
		file, err := os.Create(filename)
		if err != nil {
			LogIt(ERROR, fmt.Sprintf("Failed to create CDB list file: %s", filename), err, c.Info, c.Debug)
			continue
		}

		// Write each value to the file
		// CDB list format: key:value
		// For match_key lookup, we just need the key
		for _, value := range values {
			_, err := file.WriteString(value + ":1\n")
			if err != nil {
				LogIt(ERROR, fmt.Sprintf("Failed to write to CDB list file: %s", filename), err, c.Info, c.Debug)
				break
			}
		}

		if err := file.Close(); err != nil {
			LogIt(ERROR, fmt.Sprintf("Failed to close CDB list file: %s", filename), err, c.Info, c.Debug)
		}

		totalEntries += len(values)
		fmt.Printf("Created CDB list %s with %d entries\n", filename, len(values))
	}

	if totalEntries > 0 {
		fmt.Printf("\nTotal CDB lists: %d with %d total entries\n", len(c.CDBLists), totalEntries)
	}
}

func WriteDeploymentInstructions(c *Config) {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)

	if len(c.CDBLists) == 0 {
		return
	}

	// Generate ossec.conf snippet
	ossecConfFile := "WAZUH_CDB_CONFIG.txt"
	file, err := os.Create(ossecConfFile)
	if err != nil {
		LogIt(ERROR, fmt.Sprintf("Failed to create ossec.conf snippet file: %s", ossecConfFile), err, c.Info, c.Debug)
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
		LogIt(ERROR, fmt.Sprintf("Failed to create deployment script: %s", deployScript), err, c.Info, c.Debug)
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
	scriptFile.WriteString("echo \"Wazuh CDB Lists Deployment\"\\n")
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
	scriptFile.WriteString("  cp -v sigma_*.xml /var/ossec/etc/rules/\n")
	scriptFile.WriteString("else\n")
	scriptFile.WriteString("  scp sigma_*.xml $WAZUH_USER@$WAZUH_SERVER:/var/ossec/etc/rules/\n")
	scriptFile.WriteString("fi\n\n")
	scriptFile.WriteString("# Step 3: Set permissions\n")
	scriptFile.WriteString("echo \"[3/4] Setting permissions...\"\n")
	scriptFile.WriteString("if [ \"$WAZUH_SERVER\" = \"localhost\" ]; then\n")
	scriptFile.WriteString("  chown wazuh:wazuh /var/ossec/etc/lists/sigma_*\n")
	scriptFile.WriteString("  chown wazuh:wazuh /var/ossec/etc/rules/sigma_*.xml\n")
	scriptFile.WriteString("  chmod 640 /var/ossec/etc/lists/sigma_*\n")
	scriptFile.WriteString("  chmod 640 /var/ossec/etc/rules/sigma_*.xml\n")
	scriptFile.WriteString("else\n")
	scriptFile.WriteString("  ssh $WAZUH_USER@$WAZUH_SERVER \"chown wazuh:wazuh /var/ossec/etc/lists/sigma_* && chown wazuh:wazuh /var/ossec/etc/rules/sigma_*.xml && chmod 640 /var/ossec/etc/lists/sigma_* && chmod 640 /var/ossec/etc/rules/sigma_*.xml\"\n")
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
	scriptFile.WriteString("echo \"   <rules>\"\n")

	// Add include statements for each product
	for product := range c.Wazuh.XmlRules {
		scriptFile.WriteString(fmt.Sprintf("echo \"     <include>sigma_%s.xml</include>\"\n", strings.ToLower(product)))
	}

	scriptFile.WriteString("echo \"   </rules>\"\n")
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

func WalkSigmaRules(c *Config) []string {
	var sigmaRuleIds []string
	err := filepath.Walk(c.Sigma.RulesRoot, func(path string, f os.FileInfo, err error) error {
		if !f.IsDir() && strings.HasSuffix(path, ".yml") {
			data, err := os.ReadFile(path)
			if err != nil {
				LogIt(ERROR, "", err, c.Info, c.Debug)
				return nil
			}
			var sigmaRule SigmaRule
			err = yaml.Unmarshal(data, &sigmaRule)
			if err != nil {
				LogIt(ERROR, "", err, c.Info, c.Debug)
				c.TrackSkips.ErrorCount++
				return nil
			}
			if !slices.Contains(sigmaRuleIds, sigmaRule.ID) {
				sigmaRuleIds = append(sigmaRuleIds, sigmaRule.ID)
			}
			c.getSigmaRules(path, f, err)
		}
		return nil
	})
	if err != nil {
		LogIt(ERROR, c.Sigma.RulesRoot, err, c.Info, c.Debug)
	}
	return sigmaRuleIds
}

func PrintStats(c *Config, sigmaRuleIds []string) {
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

func main() {
	c := InitConfig()
	c.Info, c.Debug = getArgs(os.Args, c)
	LogIt(DEBUG, "", nil, c.Info, c.Debug)

	// Initialize the XmlRules map for multiple products
	c.Wazuh.XmlRules = make(map[string]*WazuhGroup)

	// Initialize the CDB Lists map
	c.CDBLists = make(map[string][]string)

	// Check if Sigma rules directory is valid
	sigmaRulesPathInfo, err := os.Stat(c.Sigma.RulesRoot)
	if err != nil {
		if os.IsNotExist(err) {
			LogIt(ERROR, fmt.Sprintf("Sigma rules directory '%s' not found. Please check the 'RulesRoot' path in your config.yaml.", c.Sigma.RulesRoot), err, c.Info, c.Debug)
		} else {
			LogIt(ERROR, fmt.Sprintf("Error accessing Sigma rules directory '%s'. Please check the 'RulesRoot' path in your config.yaml.", c.Sigma.RulesRoot), err, c.Info, c.Debug)
		}
		return
	}
	if !sigmaRulesPathInfo.IsDir() {
		LogIt(ERROR, fmt.Sprintf("The configured Sigma rules path '%s' is not a directory. Please check the 'RulesRoot' path in your config.yaml.", c.Sigma.RulesRoot), nil, c.Info, c.Debug)
		return
	}

	sigmaRuleIds := WalkSigmaRules(c)

	// Write XML rule files (one per product)
	WriteWazuhXmlRules(c)

	// Write CDB list files
	WriteCDBLists(c)

	// Write deployment instructions and helper scripts
	WriteDeploymentInstructions(c)

	// Convert map to json
	jsonData, err := json.Marshal(c.Ids.SigmaToWazuh)
	if err != nil {
		LogIt(ERROR, "", err, c.Info, c.Debug)
	}
	// Write JSON data to a file
	err = os.WriteFile(c.Wazuh.RuleIdFile, jsonData, 0644)
	if err != nil {
		LogIt(ERROR, "", err, c.Info, c.Debug)
	}

	PrintStats(c, sigmaRuleIds)
}

/*****************************************************************
UTILITY FUNCTIONS
*/

func getArgs(args []string, c *Config) (bool, bool) {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
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

const DEBUG = "debug"
const INFO = "info"
const WARN = "warn"
const ERROR = "error"

// Get function name for debugging
func printPreviousFunctionName() string {
	pc, _, _, _ := runtime.Caller(2) // 2 steps up the call stack
	functionPath := runtime.FuncForPC(pc).Name()
	return functionPath
}

func LogIt(level string, msg string, err error, info bool, debug bool) {
	log.SetOutput(os.Stdout)
	switch level {
	case ERROR:
		log.Printf("ERROR: %v - %v", msg, err)
	case WARN:
		log.Printf(" WARN: %v", msg)
	case INFO:
		if info {
			log.Printf(" INFO: %v", msg)
		}
	case DEBUG:
		if debug {
			function := printPreviousFunctionName()
			if msg != "" {
				log.Printf("DEBUG: %v - %v", function, msg)
			} else {
				log.Printf("DEBUG: %v", function)
			}
		}
	}
}

// func contains(slice []string, str string) bool {
// 	for _, v := range slice {
// 		if v == str {
// 			return true
// 		}
// 	}
// 	return false
// }
