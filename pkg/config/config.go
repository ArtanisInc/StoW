package config

import (
	"os"
	"strings"
	"stow/pkg/types"
	
	"gopkg.in/yaml.v2"
)

// Load reads and parses the config.yaml file
func Load() (*types.Config, error) {
	c := &types.Config{
		Ids: struct {
			PreviousUsed []int            `yaml:"PreviousUsed"`
			CurrentUsed  []int            `yaml:"CurrentUsed"`
			SigmaToWazuh map[string][]int `yaml:"SigmaToWazuh"`
		}{
			SigmaToWazuh: make(map[string][]int),
		},
		CDBLists: make(map[string][]string),
	}
	
	// Load main config
	if err := loadStowConfig(c); err != nil {
		return nil, err
	}
	
	// Load ID mappings
	if err := loadSigmaWazuhIdMap(c); err != nil {
		// Non-fatal, just log warning
		// Will create new file on save
	}
	
	// Initialize previous used IDs
	initPreviousUsed(c)
	
	return c, nil
}

func loadStowConfig(c *types.Config) error {
	data, err := os.ReadFile("./config.yaml")
	if err != nil {
		return err
	}
	
	err = yaml.Unmarshal(data, &c)
	if err != nil {
		return err
	}
	
	// Lowercase the FieldMaps keys for case-insensitive matching
	lowerFieldMaps := make(map[string]map[string]string)
	for product, fields := range c.Wazuh.FieldMaps {
		lowerFieldMaps[strings.ToLower(product)] = fields
	}
	c.Wazuh.FieldMaps = lowerFieldMaps
	
	return nil
}

func loadSigmaWazuhIdMap(c *types.Config) error {
	data, err := os.ReadFile(c.Wazuh.RuleIdFile)
	if err != nil {
		// Create empty file
		file, err := os.Create(c.Wazuh.RuleIdFile)
		if err != nil {
			return err
		}
		file.Close()
		return nil
	}
	
	err = yaml.Unmarshal(data, &c.Ids.SigmaToWazuh)
	if err != nil {
		return err
	}
	
	return nil
}

func initPreviousUsed(c *types.Config) {
	for _, ids := range c.Ids.SigmaToWazuh {
		c.Ids.PreviousUsed = append(c.Ids.PreviousUsed, ids...)
	}
}
