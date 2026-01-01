package strategy

import (
	"strings"

	"github.com/ArtanisInc/StoW/pkg/types"
)

// ConversionStrategy defines the interface for different rule conversion strategies
type ConversionStrategy interface {
	// GetWazuhField maps a Sigma field name to a Wazuh field path
	GetWazuhField(fieldName string, sigma *types.SigmaRule) string
	
	// GetParentRule returns the parent rule ID (if_sid) for this rule
	GetParentRule(sigma *types.SigmaRule) (string, string) // returns (type, id) where type is "sid" or "group"
	
	// GetName returns the strategy name for logging
	GetName() string
}

// StrategyFactory creates the appropriate strategy based on the Sigma rule
func StrategyFactory(sigma *types.SigmaRule, config *types.Config) ConversionStrategy {
	product := strings.ToLower(sigma.LogSource.Product)
	service := strings.ToLower(sigma.LogSource.Service)
	category := strings.ToLower(sigma.LogSource.Category)
	
	// Priority 1: Service-specific strategy (e.g., windows-security)
	if service != "" {
		productService := product + "-" + service
		
		// Check if this service uses EventID-based detection (Security, System, Application)
		if service == "security" || service == "system" || service == "application" {
			return NewEventIDStrategy(config, product, service)
		}
		
		// Check if this service has a specific mapping
		if _, ok := config.Wazuh.SidGrpMaps.ProductServiceToWazuhId[service]; ok {
			return NewServiceStrategy(config, product, service)
		}
		
		// Check product-service combination
		if _, ok := config.Wazuh.SidGrpMaps.ProductServiceToWazuhId[productService]; ok {
			return NewServiceStrategy(config, product, service)
		}
	}
	
	// Priority 2: Category-based strategy (Sysmon, built-in channels)
	if category != "" {
		return NewCategoryStrategy(config, product, category)
	}
	
	// Priority 3: Product-level fallback
	return NewProductStrategy(config, product)
}
