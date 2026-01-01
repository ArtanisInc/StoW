package strategy

import (
	"fmt"
	"strings"

	"github.com/theflakes/StoW/pkg/types"
)

// ProductStrategy is a fallback strategy for product-level rules
type ProductStrategy struct {
	config  *types.Config
	product string
}

func NewProductStrategy(config *types.Config, product string) *ProductStrategy {
	return &ProductStrategy{
		config:  config,
		product: product,
	}
}

func (s *ProductStrategy) GetName() string {
	return fmt.Sprintf("Product(%s)", s.product)
}

func (s *ProductStrategy) GetWazuhField(fieldName string, sigma *types.SigmaRule) string {
	product := strings.ToLower(s.product)
	
	// Product-level FieldMaps
	if fieldMap, ok := s.config.Wazuh.FieldMaps[product]; ok {
		if wazuhField, ok := fieldMap[fieldName]; ok {
			return wazuhField
		}
	}
	
	// Fallback to full_log
	return "full_log"
}

func (s *ProductStrategy) GetParentRule(sigma *types.SigmaRule) (string, string) {
	// Product-level rules typically don't have a parent
	// They use direct rule matching
	return "", ""
}
