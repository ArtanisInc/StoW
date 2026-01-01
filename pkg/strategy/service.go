package strategy

import (
	"fmt"
	"stow/pkg/types"
	"strings"
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
	product := strings.ToLower(s.product)
	
	// Service-specific rules use product-level FieldMaps
	if fieldMap, ok := s.config.Wazuh.FieldMaps[product]; ok {
		if wazuhField, ok := fieldMap[fieldName]; ok {
			return wazuhField
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
