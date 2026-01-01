package types

import (
	"encoding/xml"
	"os"
)

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
	XMLName xml.Name    `xml:"group"`
	Name    string      `xml:"name,attr"`
	Header  xml.Comment `xml:",comment"`
	Rules   []WazuhRule `xml:"rule"`
}

// Field represents a Wazuh rule field
type Field struct {
	Name   string `xml:"name,attr"`
	Negate string `xml:"negate,attr,omitempty"`
	Type   string `xml:"type,attr,omitempty"`
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
	Fields     []Field
	SrcIps     []IPField
	DstIps     []IPField
	ListFields []ListField
}

// WazuhRule represents a complete Wazuh detection rule
type WazuhRule struct {
	XMLName          xml.Name `xml:"rule"`
	ID               string   `xml:"id,attr"`
	Level            string   `xml:"level,attr"`
	Info             struct {
		Type  string `xml:"type,attr,omitempty"`
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
	Fields      []Field     `xml:"field,omitempty"`
}
