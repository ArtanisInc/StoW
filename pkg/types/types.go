package types

import "os"

// Config holds all configuration for StoW converter
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
		Levels             struct {
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
			CategoryToWazuhId          map[string]map[string]string `yaml:"CategoryToWazuhId"`
		} `yaml:"SidGrpMaps"`
		FieldMaps map[string]map[string]string `yaml:"FieldMaps"`
		XmlRules  map[string]*WazuhGroup
	} `yaml:"Wazuh"`
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
	CDBLists map[string][]string
}

// SigmaRule represents a parsed Sigma detection rule
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
		Category string `yaml:"category"`
		Product  string `yaml:"product"`
		Service  string `yaml:"service"`
	} `yaml:"logsource"`
	Detection map[string]any `yaml:"detection"`
	Level     string         `yaml:"level"`
}

// WazuhGroup represents a group of Wazuh rules
type WazuhGroup struct {
	Name  string
	Rules []WazuhRule
}

// Field represents a Wazuh rule field
type Field struct {
	Name    string
	Value   string
	Type    string
	Negate  bool
	Comment string
}

// IPField represents an IP-related field (source or destination)
type IPField struct {
	Name   string
	Value  string
	IsSrc  bool
	IsDst  bool
	Negate bool
}

// ListField represents a field that should become a CDB list
type ListField struct {
	Name   string
	Values []string
	Negate bool
}

// RuleFields holds all fields for a Wazuh rule
type RuleFields struct {
	Fields    []Field
	SrcIps    []IPField
	DstIps    []IPField
	ListFields []ListField
}

// WazuhRule represents a complete Wazuh detection rule
type WazuhRule struct {
	ID          int
	Level       int
	IfSid       string
	IfGroup     string
	SigmaID     string
	URL         string
	Description string
	Info        []string
	Options     []string
	Author      string
	Date        string
	Modified    string
	Status      string
	Mitre       []string
	Group       string
	Fields      []Field
	SrcIps      []IPField
	DstIps      []IPField
	ListFields  []ListField
}
