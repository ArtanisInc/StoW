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
		RulesFile          string         `yaml:"RulesFile"`
		RuleIdFile         string         `yaml:"RuleIdFile"`
		RuleIdStart        int            `yaml:"RuleIdStart"`
		MaxRulesPerFile    int            `yaml:"MaxRulesPerFile"`
		ProductRuleIdStart map[string]int `yaml:"ProductRuleIdStart"`
		WriteRules         os.File
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
			SigmaIdToWazuhGroup        map[string]string            `yaml:"SigmaIdToWazuhGroup"`
			SigmaIdToWazuhId           map[string]string            `yaml:"SigmaIdToWazuhId"`
			ProductServiceToWazuhGroup map[string]string            `yaml:"ProductServiceToWazuhGroup"`
			ProductServiceToWazuhId    map[string]string            `yaml:"ProductServiceToWazuhId"`
			CategoryToWazuhGroup       map[string]string            `yaml:"CategoryToWazuhGroup"`
			CategoryToWazuhId          map[string]map[string]string `yaml:"CategoryToWazuhId"` // Product -> Category -> Rule IDs
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
	Mitre            *struct {
		IDs []string `xml:"id,omitempty"`
	} `xml:"mitre,omitempty"`
	Description string      `xml:"description"`
	DecodedAs   string      `xml:"decoded_as,omitempty"`
	Options     []string    `xml:"options,omitempty"`
	Groups      string      `xml:"group,omitempty"`
	IfSid       string      `xml:"if_sid,omitempty"`
	IfGroup     string      `xml:"if_group,omitempty"`
	SrcIps      []IPField   `xml:"srcip,omitempty"`
	DstIps      []IPField   `xml:"dstip,omitempty"`
	Lists       []ListField `xml:"list,omitempty"`
	Fields      []Field     `xml:"field"`
}

// sanitizeXMLComment ensures the string is safe to use in an XML comment
// XML comments cannot contain "--" and cannot start or end with "-"
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

// validateConfig checks if required configuration values are set and valid
func validateConfig(c *Config) error {
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
			// Check for overlaps (assuming 10000 IDs per product as per comments)
			rangeStart := startId / 10000
			if existingProduct, exists := usedRanges[rangeStart]; exists {
				return fmt.Errorf("product %s rule ID range overlaps with %s", product, existingProduct)
			}
			usedRanges[rangeStart] = product
		}
	}

	return nil
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

func TrackIdMaps(sigmaId string, product string, c *Config) string {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)

	// Get the starting ID for this product, fallback to default RuleIdStart if not configured
	startId, ok := c.Wazuh.ProductRuleIdStart[product]
	if !ok {
		startId = c.Wazuh.RuleIdStart
	}

	// has this Sigma rule been converted previously, reuse its Wazuh rule IDs
	if ids, ok := c.Ids.SigmaToWazuh[sigmaId]; ok {
		for _, id := range ids {
			if !slices.Contains(c.Ids.CurrentUsed, id) {
				c.Ids.CurrentUsed = append(c.Ids.CurrentUsed, id)
				return strconv.Itoa(id)
			}
		}
	}

	// new Sigma rule, find an unused Wazuh rule ID starting from product-specific ID
	currentId := startId
	for slices.Contains(c.Ids.PreviousUsed, currentId) ||
		slices.Contains(c.Ids.CurrentUsed, currentId) {
		currentId++
	}

	AddToMapStrToInts(c, sigmaId, currentId)
	c.Ids.CurrentUsed = append(c.Ids.CurrentUsed, currentId)
	return strconv.Itoa(currentId)
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
	// Priority order: Sigma ID > Service > Category > Product
	switch {
	case c.Wazuh.SidGrpMaps.SigmaIdToWazuhGroup[sigma.ID] != "":
		return "grp", c.Wazuh.SidGrpMaps.SigmaIdToWazuhGroup[sigma.ID]
	case c.Wazuh.SidGrpMaps.SigmaIdToWazuhId[sigma.ID] != "":
		return "sid", c.Wazuh.SidGrpMaps.SigmaIdToWazuhId[sigma.ID]
	case c.Wazuh.SidGrpMaps.ProductServiceToWazuhGroup[sigma.LogSource.Service] != "":
		return "grp", c.Wazuh.SidGrpMaps.ProductServiceToWazuhGroup[sigma.LogSource.Service]
	case c.Wazuh.SidGrpMaps.CategoryToWazuhGroup[sigma.LogSource.Category] != "":
		return "grp", c.Wazuh.SidGrpMaps.CategoryToWazuhGroup[sigma.LogSource.Category]
	case c.Wazuh.SidGrpMaps.ProductServiceToWazuhGroup[sigma.LogSource.Product] != "":
		return "grp", c.Wazuh.SidGrpMaps.ProductServiceToWazuhGroup[sigma.LogSource.Product]
	case c.Wazuh.SidGrpMaps.ProductServiceToWazuhId[sigma.LogSource.Service] != "":
		return "sid", c.Wazuh.SidGrpMaps.ProductServiceToWazuhId[sigma.LogSource.Service]
	case c.Wazuh.SidGrpMaps.CategoryToWazuhId[sigma.LogSource.Product] != nil && c.Wazuh.SidGrpMaps.CategoryToWazuhId[sigma.LogSource.Product][sigma.LogSource.Category] != "":
		// Product-specific category mapping (e.g., Windows process_creation -> 61603, Linux process_creation -> 200111)
		return "sid", c.Wazuh.SidGrpMaps.CategoryToWazuhId[sigma.LogSource.Product][sigma.LogSource.Category]
	case c.Wazuh.SidGrpMaps.ProductServiceToWazuhId[sigma.LogSource.Product] != "":
		return "sid", c.Wazuh.SidGrpMaps.ProductServiceToWazuhId[sigma.LogSource.Product]
	default:
		return "sid", ""
	}
}

func GetGroups(sigma *SigmaRule, c *Config) string {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
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

// fieldModifiers holds the parsed modifiers from a Sigma field key
type fieldModifiers struct {
	isRegex    bool
	isB64      bool
	isCIDR     bool
	startsWith bool
	endsWith   bool
	hasAll     bool
}

// parseFieldModifiers extracts and parses modifiers from a field key (e.g., "field|contains|base64")
func parseFieldModifiers(parts []string, value any) (fieldModifiers, any) {
	mods := fieldModifiers{}

	if len(parts) <= 1 {
		return mods, value
	}

	for _, modifier := range parts[1:] {
		switch strings.ToLower(modifier) {
		case "contains":
			// Default behavior, no special handling needed
		case "startswith":
			mods.startsWith = true
		case "endswith":
			mods.endsWith = true
		case "all":
			mods.hasAll = true
		case "re":
			mods.isRegex = true
		case "base64offset", "base64":
			mods.isB64 = true
		case "windash":
			value = HandleWindash(value)
		case "cidr":
			mods.isCIDR = true
		}
	}

	return mods, value
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
func handleCIDRField(fieldName string, values []string, selectionKey string, selectionNegations map[string]bool, srcIps *[]IPField, dstIps *[]IPField, c *Config) {
	ipType := determineIPFieldType(fieldName)

	negate := ""
	if selectionNegations[selectionKey] {
		negate = "yes"
	}

	for _, v := range values {
		ipField := IPField{
			Negate: negate,
			Value:  v,
		}

		switch ipType {
		case ipFieldSource:
			*srcIps = append(*srcIps, ipField)
			LogIt(INFO, fmt.Sprintf("Added srcip CIDR field: %s (negate=%s)", v, negate), nil, c.Info, c.Debug)
		case ipFieldDestination:
			*dstIps = append(*dstIps, ipField)
			LogIt(INFO, fmt.Sprintf("Added dstip CIDR field: %s (negate=%s)", v, negate), nil, c.Info, c.Debug)
		case ipFieldGeneric:
			// Generic IP field - default to srcip
			*srcIps = append(*srcIps, ipField)
			LogIt(INFO, fmt.Sprintf("Added srcip CIDR field (generic IP): %s (negate=%s)", v, negate), nil, c.Info, c.Debug)
		default:
			// If we can't determine IP direction, log a warning and skip
			LogIt(WARN, fmt.Sprintf("CIDR modifier used on non-IP field: %s", fieldName), nil, c.Info, c.Debug)
		}
	}
}

// isSimpleValue checks if a value is simple enough for exact field matching
// Returns true if the value contains no wildcards, regex special chars, or complex patterns
func isSimpleValue(v string) bool {
	// Check for regex/wildcard characters that require PCRE2
	return !strings.ContainsAny(v, "*?|()[]{}\\^$+.")
}

// needsCaseInsensitive determines if case-insensitive matching is needed for a field
// Returns false for fields that have predictable case (like audit.type which is always uppercase)
func needsCaseInsensitive(fieldName string, product string) bool {
	product = strings.ToLower(product)
	fieldName = strings.ToLower(fieldName)

	// Linux auditd fields that are always uppercase or lowercase
	if product == "linux" {
		switch fieldName {
		case "audit.type", "type":
			return false // Always uppercase: EXECVE, SYSCALL, PATH, etc.
		case "audit.syscall", "syscall":
			return false // Numeric values
		}
	}

	// Windows fields that are predictable or numeric (don't need case-insensitive)
	if product == "windows" {
		switch fieldName {
		// Numeric fields
		case "win.system.eventid", "eventid":
			return false // Numeric values
		case "win.system.level", "level":
			return false // Numeric values
		case "win.eventdata.logontype", "logontype":
			return false // Numeric logon type (2, 3, 7, 9, 10, etc.)
		case "win.eventdata.processid", "processid":
			return false // Numeric process ID
		case "win.eventdata.threadid", "threadid":
			return false // Numeric thread ID
		case "win.eventdata.status", "status":
			return false // Hex status codes (0xC0000XXX)

		// GUIDs and hash fields (always uppercase hex or lowercase, but consistent)
		case "win.eventdata.guid", "guid":
			return false // GUIDs have fixed format
		case "win.eventdata.hashes", "hashes":
			return false // SHA256/MD5 hashes are case-consistent

		// Provider names are case-sensitive in Windows Event Log
		case "win.eventdata.providername", "providername":
			return false // Provider names are case-preserving
		case "win.system.provider_name", "provider_name":
			return false // Provider names are case-preserving
		}
	}

	// Default: use case-insensitive for user input and command lines
	return true
}

// buildFieldValue constructs a regex pattern value based on the input value and modifiers
// Phase 2 optimization: Intelligently adds (?i) only when needed
func buildFieldValue(v string, mods fieldModifiers, fieldName string, product string) string {
	if mods.isB64 {
		return HandleB64Offsets(v)
	}

	if mods.isRegex {
		return v
	}

	// Build regex pattern with anchors if needed
	pattern := regexp.QuoteMeta(v)

	// Phase 2: Determine if case-insensitive is needed
	casePrefix := ""
	if needsCaseInsensitive(fieldName, product) {
		casePrefix = "(?i)"
	}

	if mods.startsWith || mods.endsWith {
		prefix := ""
		suffix := ""
		if mods.startsWith {
			prefix = "^"
		}
		if mods.endsWith {
			suffix = "$"
		}
		return casePrefix + prefix + pattern + suffix
	}

	return casePrefix + pattern
}

// processDetectionField extracts and processes a single field from a Sigma detection.
func processDetectionField(selectionKey string, key string, value any, sigma *SigmaRule, c *Config, fields *[]Field, srcIps *[]IPField, dstIps *[]IPField, selectionNegations map[string]bool) {
	LogIt(INFO, fmt.Sprintf("processDetectionField key: %s, value: %v", key, value), nil, c.Info, c.Debug)

	// Parse field name and modifiers
	parts := strings.Split(key, "|")
	fieldName := parts[0]
	mods, value := parseFieldModifiers(parts, value)

	wazuhField := GetWazuhField(fieldName, sigma, c)

	field := Field{
		Name: wazuhField,
		Type: "pcre2",
	}

	// Apply negation if this selectionKey is marked as negated
	if selectionNegations[selectionKey] {
		field.Negate = "yes"
	}

	// Handle CIDR modifier for IP fields
	if mods.isCIDR {
		values := GetFieldValues(value, fieldName, c)
		handleCIDRField(fieldName, values, selectionKey, selectionNegations, srcIps, dstIps, c)
		return
	}

	values := GetFieldValues(value, fieldName, c)

	// Phase 2: Check if we can use exact field matching instead of regex
	canUseExact := !mods.isRegex && !mods.startsWith && !mods.endsWith && !mods.isB64
	if canUseExact {
		for _, v := range values {
			if !isSimpleValue(v) {
				canUseExact = false
				break
			}
		}
	}

	// Handle 'all' modifier - create separate field for each value
	if mods.hasAll {
		for _, v := range values {
			newField := field
			// Phase 2: Use exact matching if possible
			if canUseExact && len(values) == 1 {
				newField.Type = ""
				newField.Value = v
			} else {
				newField.Value = buildFieldValue(v, mods, wazuhField, sigma.LogSource.Product)
			}
			*fields = append(*fields, newField)
			LogIt(INFO, fmt.Sprintf("processDetectionField appended field: %v", newField), nil, c.Info, c.Debug)
		}
		return
	}

	// Build combined field value (OR logic)
	var fieldValues []string
	for _, v := range values {
		fieldValues = append(fieldValues, buildFieldValue(v, mods, wazuhField, sigma.LogSource.Product))
	}

	if len(fieldValues) == 0 {
		LogIt(DEBUG, fmt.Sprintf("No processed fieldValues for field '%s'", fieldName), nil, c.Info, c.Debug)
		return
	}

	// Construct final field value
	if mods.isRegex {
		field.Value = strings.Join(fieldValues, "|")
	} else {
		combinedValue := strings.Join(fieldValues, "|")
		if len(fieldValues) > 1 {
			combinedValue = "(?:" + combinedValue + ")"
		}
		if mods.startsWith {
			combinedValue = "^" + combinedValue
		}
		if mods.endsWith {
			combinedValue = combinedValue + "$"
		}
		field.Value = combinedValue
	}

	// Phase 2: Use exact matching for simple single values with no modifiers
	if canUseExact && len(values) == 1 {
		field.Type = ""
		field.Value = values[0]
		LogIt(INFO, fmt.Sprintf("Phase 2: Using exact field matching for %s=%s", wazuhField, values[0]), nil, c.Info, c.Debug)
	}

	*fields = append(*fields, field)
	LogIt(INFO, fmt.Sprintf("processDetectionField appended field: %v", field), nil, c.Info, c.Debug)
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

// filterMitreTags filters and formats MITRE ATT&CK tags from Sigma rules
// Removes tactic-only tags and keeps only technique IDs in proper format
// Input:  ["attack.credential-access", "attack.t1003.001", "attack.persistence", "attack.t1190"]
// Output: ["T1003.001", "T1190"]
func filterMitreTags(tags []string) []string {
	var filtered []string

	for _, tag := range tags {
		// Remove "attack." prefix if present
		tag = strings.TrimPrefix(tag, "attack.")

		// Check if this is a technique ID (starts with 't' followed by digits)
		// Technique format: t1234 or t1234.567
		if len(tag) > 1 && strings.HasPrefix(strings.ToLower(tag), "t") {
			// Check if second character is a digit
			if len(tag) > 1 && tag[1] >= '0' && tag[1] <= '9' {
				// Convert to uppercase format (T1003.001)
				filtered = append(filtered, strings.ToUpper(tag))
			}
		}
		// Skip tactic-only tags (credential-access, persistence, etc.)
	}

	return filtered
}

// processOversizedFields checks for fields exceeding Wazuh's size limits and converts them to CDB lists
// Returns the processed fields and list fields, or an error if processing fails
func processOversizedFields(ruleFields RuleFields, sigmaID string, c *Config) ([]Field, []ListField, error) {
	const maxFieldLength = 4096
	var finalFields []Field
	var listFields []ListField

	for i, field := range ruleFields.Fields {
		if len(field.Value) <= maxFieldLength {
			finalFields = append(finalFields, field)
			continue
		}

		// Field exceeds limit - convert to CDB list
		values := extractValuesFromRegex(field.Value)

		if len(values) == 0 {
			LogIt(WARN, fmt.Sprintf("Rule %s has field value exceeding limit but couldn't extract values. Skipping rule.", sigmaID), nil, c.Info, c.Debug)
			c.TrackSkips.FieldTooLong++
			c.TrackSkips.RulesSkipped++
			return nil, nil, fmt.Errorf("field value too long and cannot be extracted")
		}

		// Create a CDB list name using Sigma ID
		listName := fmt.Sprintf("sigma_%s_%d_%s", strings.ReplaceAll(sigmaID, "-", ""), i, sanitizeFieldName(field.Name))

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

		LogIt(INFO, fmt.Sprintf("Rule %s field '%s' converted to CDB list with %d values (%d chars → CDB)", sigmaID, field.Name, len(values), len(field.Value)), nil, c.Info, c.Debug)
		c.TrackSkips.ConvertedToCDB++
	}

	return finalFields, listFields, nil
}

// populateRuleMetadata fills in the Wazuh rule metadata from Sigma rule data
func populateRuleMetadata(rule *WazuhRule, sigma *SigmaRule, url string, product string, c *Config) {
	rule.ID = TrackIdMaps(sigma.ID, product, c)
	rule.Level = strconv.Itoa(GetLevel(sigma.Level, c))
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
	rule.Options = GetOptions(sigma, c)
	rule.Groups = GetGroups(sigma, c)

	// Set if_sid or if_group dependencies
	ifType, value := GetIfGrpSid(sigma, c)
	if ifType == "grp" {
		rule.IfGroup = value
	} else {
		rule.IfSid = value
	}
}

// optimizeLinuxRule converts audit.type field matching to if_sid for better performance
// This optimization applies to Linux/auditd rules that explicitly check audit.type field
// OR use fields from specific auditd decoders without specifying if_sid
func optimizeLinuxRule(rule *WazuhRule) {
	// Skip if rule already has if_sid (already optimized)
	if rule.IfSid != "" {
		return
	}

	// Map audit.type values to their corresponding parent rule IDs (case-insensitive)
	auditTypeToIfSid := map[string]string{
		"execve":         "200111", // auditd-execve (process execution)
		"syscall":        "200110", // auditd-syscall (system calls)
		"path":           "200112", // auditd-path (file access)
		"config_change":  "200113", // auditd-config_change
		"user_acct":      "200114", // auditd-user_and_cred
		"user_auth":      "200114", // auditd-user_and_cred
		"add_user":       "200114", // auditd-user_and_cred (user management)
		"del_user":       "200114", // auditd-user_and_cred (user management)
		"user_chauthtok": "200114", // auditd-user_and_cred (password change)
		"service_stop":   "200115", // auditd-service_stop (service management)
		"tty":            "200116", // auditd-tty (TTY/terminal events)
		"user_tty":       "200116", // auditd-tty (user TTY events)
	}

	// Look for audit.type field (exact match only, skip pcre2)
	var auditTypeValue string
	var auditTypeIndex int = -1

	for i, field := range rule.Fields {
		if field.Name == "audit.type" && field.Type == "" {
			// Found exact match audit.type field (not pcre2)
			auditTypeValue = strings.ToLower(field.Value) // Normalize to lowercase
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
	// This pattern matches both TTY and USER_TTY types, which both map to parent rule 200116
	for i, field := range rule.Fields {
		if field.Name == "audit.type" && field.Type == "pcre2" {
			// Check if this is the TTY|USER_TTY pattern
			if strings.Contains(field.Value, "TTY") && strings.Contains(field.Value, "USER_TTY") {
				// Set if_sid to TTY parent rule
				rule.IfSid = "200116"
				// Remove the audit.type field (no longer needed)
				rule.Fields = append(rule.Fields[:i], rule.Fields[i+1:]...)
				return
			}
		}
	}

	// NEW: Field-based decoder detection
	// If no audit.type was found, detect which decoder is needed based on field names
	// This handles rules that use auditd decoder fields without explicitly specifying audit.type
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
		rule.IfSid = "200111" // auditd-execve
		return
	}
	if hasPathField {
		rule.IfSid = "200112" // auditd-path
		return
	}
	if hasSyscallField {
		rule.IfSid = "200110" // auditd-syscall
		return
	}
	if hasConfigChangeField {
		rule.IfSid = "200113" // auditd-config_change
		return
	}
	if hasTTYField {
		rule.IfSid = "200116" // auditd-tty
		return
	}

	// If no decoder-specific fields found, this rule likely uses full_log matching
	// or is not an auditd rule (e.g., clamav, cron, sshd) - no if_sid needed
}

// BuildRule constructs a Wazuh rule from a Sigma rule detection
func BuildRule(sigma *SigmaRule, url string, product string, c *Config, detections map[string]any, selectionNegations map[string]bool) WazuhRule {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)

	ruleFields := GetFields(detections, sigma, c, selectionNegations)
	if len(ruleFields.Fields) == 0 && len(ruleFields.SrcIps) == 0 && len(ruleFields.DstIps) == 0 {
		LogIt(WARN, "No fields found for rule: "+sigma.ID+" URL: "+url, nil, c.Info, c.Debug)
		return WazuhRule{}
	}

	// Process oversized fields, converting to CDB lists if needed
	finalFields, listFields, err := processOversizedFields(ruleFields, sigma.ID, c)
	if err != nil {
		return WazuhRule{}
	}

	// Update ruleFields with the processed fields
	ruleFields.Fields = finalFields
	ruleFields.ListFields = listFields

	// Build the Wazuh rule
	var rule WazuhRule
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

// filterBooleanPlaceholders removes __TRUE__ and __FALSE__ placeholders from a DNF set
// Returns the filtered set and whether the set should be skipped (if it contains __FALSE__)
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
// Handles list-of-maps (OR logic requiring separate rules) and simple value lists
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
func buildAndStoreRules(detectionSets []map[string]any, selectionNegations map[string]bool, sigmaRule *SigmaRule, url string, c *Config) {
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
			c.Wazuh.XmlRules[product] = &WazuhGroup{
				Name: product + ",",
			}
		}
		c.Wazuh.XmlRules[product].Rules = append(c.Wazuh.XmlRules[product].Rules, rule)
	}
}

// ProcessDnfSets converts DNF (Disjunctive Normal Form) sets into Wazuh rules
// Each DNF set represents an AND group of selections that forms one or more Wazuh rules
func ProcessDnfSets(passingSets [][]string, detections map[string]any, sigmaRule *SigmaRule, url string, c *Config) {
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

// generateLinuxParentRules creates the base auditd parent rules for Linux
// Phase 3: Auto-generate parent rules that Sigma-converted rules depend on
func generateLinuxParentRules() []WazuhRule {
	return []WazuhRule{
		{
			ID:          "200110",
			Level:       "3",
			DecodedAs:   "auditd-syscall",
			Description: "Audit: SYSCALL Messages grouped.",
			Options:     []string{"no_full_log"},
			Groups:      "linux,auditd,syscall,",
		},
		{
			ID:          "200111",
			Level:       "3",
			DecodedAs:   "auditd-execve",
			Description: "Audit: EXECVE Messages grouped.",
			Options:     []string{"no_full_log"},
			Groups:      "linux,auditd,execve,",
		},
		{
			ID:          "200112",
			Level:       "3",
			DecodedAs:   "auditd-path",
			Description: "Audit: PATH Messages grouped.",
			Options:     []string{"no_full_log"},
			Groups:      "linux,auditd,path,",
		},
		{
			ID:          "200113",
			Level:       "5",
			DecodedAs:   "auditd-config_change",
			Description: "Audit: CONFIG_CHANGE Messages grouped.",
			Options:     []string{"no_full_log"},
			Groups:      "linux,auditd,config_change,",
		},
		{
			ID:          "200114",
			Level:       "3",
			DecodedAs:   "auditd-user_and_cred",
			Description: "Audit: USER credentials Messages grouped.",
			Options:     []string{"no_full_log"},
			Groups:      "linux,auditd,user_and_cred,",
		},
		{
			ID:          "200115",
			Level:       "3",
			DecodedAs:   "auditd-service_stop",
			Description: "Audit: SERVICE_STOP Messages grouped.",
			Options:     []string{"no_full_log"},
			Groups:      "linux,auditd,service_stop,",
		},
		{
			ID:          "200116",
			Level:       "3",
			DecodedAs:   "auditd-tty",
			Description: "Audit: TTY/USER_TTY Messages grouped.",
			Options:     []string{"no_full_log"},
			Groups:      "linux,auditd,tty,",
		},
	}
}

// generatePowerShellParentRules creates PowerShell-specific parent rules for Windows
// These rules filter PowerShell events by EventID and ProviderName for optimal performance
func generatePowerShellParentRules() []WazuhRule {
	return []WazuhRule{
		{
			ID:          "200000",
			Level:       "3",
			Description: "PowerShell: Script Block Logging (Event 4104)",
			Options:     []string{"no_full_log"},
			Groups:      "windows,powershell,ps_script,",
			Fields: []Field{
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
			Fields: []Field{
				{Name: "win.system.eventID", Value: "4103", Type: ""},
				{Name: "win.system.channel", Value: "Microsoft-Windows-PowerShell/Operational", Type: ""},
			},
		},
		{
			ID:          "200002",
			Level:       "5",
			Description: "PowerShell: Classic PowerShell Engine Start (Event 400)",
			Options:     []string{"no_full_log"},
			Groups:      "windows,powershell,ps_classic_start,",
			Fields: []Field{
				{Name: "win.system.eventID", Value: "400", Type: ""},
				{Name: "win.system.provider_name", Value: "PowerShell", Type: ""},
			},
		},
		{
			ID:          "200003",
			Level:       "5",
			Description: "PowerShell: Classic Provider Start (Event 600)",
			Options:     []string{"no_full_log"},
			Groups:      "windows,powershell,ps_classic_provider_start,",
			Fields: []Field{
				{Name: "win.system.eventID", Value: "600", Type: ""},
				{Name: "win.system.provider_name", Value: "PowerShell", Type: ""},
			},
		},
	}
}

func WriteWazuhXmlRules(c *Config) {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)

	// Iterate through each product and write separate XML files
	for product, xmlRules := range c.Wazuh.XmlRules {
		if len(xmlRules.Rules) == 0 {
			continue // Skip empty rule sets
		}

		// Phase 3: Prepend Linux parent rules if this is a Linux product
		if product == "linux" {
			parentRules := generateLinuxParentRules()
			// Prepend parent rules to the beginning
			xmlRules.Rules = append(parentRules, xmlRules.Rules...)
			LogIt(INFO, fmt.Sprintf("Phase 3: Added %d Linux parent rules to %s", len(parentRules), product), nil, c.Info, c.Debug)
		}

		// Phase 5: Prepend PowerShell parent rules if this is a Windows product
		if product == "windows" {
			parentRules := generatePowerShellParentRules()
			// Prepend parent rules to the beginning
			xmlRules.Rules = append(parentRules, xmlRules.Rules...)
			LogIt(INFO, fmt.Sprintf("Phase 5: Added %d PowerShell parent rules to %s", len(parentRules), product), nil, c.Info, c.Debug)
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
				partRules := &WazuhGroup{
					Rules: xmlRules.Rules[startIdx:endIdx],
				}

				// Create filename with part number and ID prefix
				filename := fmt.Sprintf("%d-sigma_%s_part%d.xml", startId, product, part+1)

				// Write the part file
				if err := writeXmlFile(filename, partRules, c); err != nil {
					LogIt(ERROR, fmt.Sprintf("Failed to write %s", filename), err, c.Info, c.Debug)
					continue
				}

				fmt.Printf("  Created %s with %d rules\n", filename, len(partRules.Rules))
			}
		} else {
			// Write single file (no splitting needed) with ID prefix
			filename := fmt.Sprintf("%d-sigma_%s.xml", startId, product)

			if err := writeXmlFile(filename, xmlRules, c); err != nil {
				LogIt(ERROR, fmt.Sprintf("Failed to write %s", filename), err, c.Info, c.Debug)
				continue
			}

			fmt.Printf("Created %s with %d rules\n", filename, len(xmlRules.Rules))
		}
	}
}

// writeXmlFile writes a WazuhGroup to an XML file
func writeXmlFile(filename string, xmlRules *WazuhGroup, c *Config) error {
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
	scriptFile.WriteString("echo \"   <ruleset>\"\n")

	// Find all generated sigma XML files (including part files)
	xmlFiles, err := filepath.Glob("sigma_*.xml")
	if err != nil {
		LogIt(ERROR, "Failed to find generated XML files", err, c.Info, c.Debug)
	} else {
		// Sort for consistent output
		for _, xmlFile := range xmlFiles {
			scriptFile.WriteString(fmt.Sprintf("echo \"     <include>%s</include>\"\n", xmlFile))
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

	// Validate configuration
	if err := validateConfig(c); err != nil {
		LogIt(ERROR, fmt.Sprintf("Configuration validation failed: %v", err), nil, c.Info, c.Debug)
		log.Fatal("Please fix the configuration errors and try again.")
	}

	// Initialize the XmlRules map for multiple products
	c.Wazuh.XmlRules = make(map[string]*WazuhGroup)

	// Initialize the CDB Lists map
	c.CDBLists = make(map[string][]string)

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
