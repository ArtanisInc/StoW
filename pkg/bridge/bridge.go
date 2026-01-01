package bridge

// Bridge package provides compatibility layer between old stow.go and new packages
// This allows gradual migration without breaking existing functionality

import (
	"github.com/ArtanisInc/StoW/pkg/strategy"
	"github.com/ArtanisInc/StoW/pkg/types"
)

// GetFieldMapper returns a strategy for field mapping
// This can be used in stow.go to gradually migrate to strategy pattern
func GetFieldMapper(sigma *types.SigmaRule, config *types.Config) strategy.ConversionStrategy {
	return strategy.StrategyFactory(sigma, config)
}

// ConvertFieldName converts a Sigma field name to Wazuh field using strategy pattern
func ConvertFieldName(fieldName string, sigma *types.SigmaRule, config *types.Config) string {
	strat := GetFieldMapper(sigma, config)
	return strat.GetWazuhField(fieldName, sigma)
}

// GetParentRuleID returns the parent rule ID for a Sigma rule using strategy pattern
func GetParentRuleID(sigma *types.SigmaRule, config *types.Config) (string, string) {
	strat := GetFieldMapper(sigma, config)
	return strat.GetParentRule(sigma)
}
