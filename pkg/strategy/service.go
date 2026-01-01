package strategy

import (
	"fmt"
	"strings"

	"github.com/theflakes/StoW/pkg/types"
)

// ServiceStrategy handles service-specific channels (msexchange, iis, wmi, etc.)
type ServiceStrategy struct {
	config  *types.Config
	product string
	service string
}

func NewServiceStrategy(config *types.Config, product string, service string) *ServiceStrategy {
	return &ServiceStrategy{
		config:  config,
		product: product,
		service: service,
	}
}

func (s *ServiceStrategy) GetName() string {
	return fmt.Sprintf("Service(%s/%s)", s.product, s.service)
}

func (s *ServiceStrategy) GetWazuhField(fieldName string, sigma *types.SigmaRule) string {
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

func (s *ServiceStrategy) GetParentRule(sigma *types.SigmaRule) (string, string) {
	service := strings.ToLower(s.service)
	productService := strings.ToLower(s.product) + "-" + service
	
	// Try product-service combination first
	if parentId, ok := s.config.Wazuh.SidGrpMaps.ProductServiceToWazuhId[productService]; ok {
		return "sid", parentId
	}
	
	// Try service alone
	if parentId, ok := s.config.Wazuh.SidGrpMaps.ProductServiceToWazuhId[service]; ok {
		return "sid", parentId
	}
	
	// No parent found
	return "", ""
}
