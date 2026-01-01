package strategy

import (
	"fmt"
	"strings"

	"github.com/theflakes/StoW/pkg/types"
)

// EventIDStrategy handles Security/System/Application channels that use EventID-based detection
type EventIDStrategy struct {
	config  *types.Config
	product string
	service string
}

func NewEventIDStrategy(config *types.Config, product string, service string) *EventIDStrategy {
	return &EventIDStrategy{
		config:  config,
		product: product,
		service: service,
	}
}

func (s *EventIDStrategy) GetName() string {
	return fmt.Sprintf("EventID(%s/%s)", s.product, s.service)
}

func (s *EventIDStrategy) GetWazuhField(fieldName string, sigma *types.SigmaRule) string {
	product := strings.ToLower(s.product)
	
	// EventID-based rules use product-level FieldMaps
	if fieldMap, ok := s.config.Wazuh.FieldMaps[product]; ok {
		if wazuhField, ok := fieldMap[fieldName]; ok {
			return wazuhField
		}
	}
	
	// Fallback to full_log
	return "full_log"
}

func (s *EventIDStrategy) GetParentRule(sigma *types.SigmaRule) (string, string) {
	service := strings.ToLower(s.service)
	
	// EventID-based rules use service-specific parent rules
	// These are auto-generated based on EventID (200100-200103)
	if parentId, ok := s.config.Wazuh.SidGrpMaps.ProductServiceToWazuhId[service]; ok {
		return "sid", parentId
	}
	
	// No parent found
	return "", ""
}
