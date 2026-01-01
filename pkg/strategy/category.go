package strategy

import (
	"fmt"
	"strings"

	"github.com/ArtanisInc/StoW/pkg/types"
)

// CategoryStrategy handles Sysmon and category-based built-in channels
type CategoryStrategy struct {
	config   *types.Config
	product  string
	category string
}

func NewCategoryStrategy(config *types.Config, product string, category string) *CategoryStrategy {
	return &CategoryStrategy{
		config:   config,
		product:  product,
		category: category,
	}
}

func (s *CategoryStrategy) GetName() string {
	return fmt.Sprintf("Category(%s/%s)", s.product, s.category)
}

func (s *CategoryStrategy) GetWazuhField(fieldName string, sigma *types.SigmaRule) string {
	// Normalize field name to lowercase for case-insensitive matching
	// This allows Sigma fields like "SYSCALL" to match config mappings like "syscall"
	fieldNameLower := strings.ToLower(fieldName)

	// Try both original case and lowercase for product (config may use "Linux" or "linux")
	products := []string{s.product, strings.ToLower(s.product), strings.Title(strings.ToLower(s.product))}

	for _, product := range products {
		if fieldMap, ok := s.config.Wazuh.FieldMaps[product]; ok {
			if wazuhField, ok := fieldMap[fieldNameLower]; ok {
				return wazuhField
			}
		}
	}

	// Fallback to full_log
	return "full_log"
}

func (s *CategoryStrategy) GetParentRule(sigma *types.SigmaRule) (string, string) {
	product := strings.ToLower(s.product)
	category := strings.ToLower(s.category)
	
	// Check product-specific category mapping
	if categoryMap, ok := s.config.Wazuh.SidGrpMaps.CategoryToWazuhId[product]; ok {
		if parentId, ok := categoryMap[category]; ok {
			return "sid", parentId
		}
	}
	
	// Check if there's a service-based parent
	if sigma.LogSource.Service != "" {
		service := strings.ToLower(sigma.LogSource.Service)
		if parentId, ok := s.config.Wazuh.SidGrpMaps.ProductServiceToWazuhId[service]; ok {
			return "sid", parentId
		}
	}
	
	// No parent found
	return "", ""
}
