package parser

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/ArtanisInc/StoW/pkg/types"
	"gopkg.in/yaml.v3"
)

// ParseSigmaFile reads and parses a single Sigma YAML file
func ParseSigmaFile(path string) (*types.SigmaRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	
	var sigma types.SigmaRule
	err = yaml.Unmarshal(data, &sigma)
	if err != nil {
		return nil, err
	}
	
	return &sigma, nil
}

// WalkSigmaRules walks a directory tree and collects all Sigma rule file paths
func WalkSigmaRules(rulesRoot string) ([]string, error) {
	var rulePaths []string
	
	err := filepath.Walk(rulesRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".yml") {
			rulePaths = append(rulePaths, path)
		}
		return nil
	})
	
	return rulePaths, err
}
