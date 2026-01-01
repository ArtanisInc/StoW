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

func (s *ProductStrategy) GetParentRule(sigma *types.SigmaRule) (string, string) {
	// Product-level rules typically don't have a parent
	// They use direct rule matching
	return "", ""
}
