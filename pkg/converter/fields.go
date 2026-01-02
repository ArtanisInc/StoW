package converter

import (
	"regexp"
	"strings"

	"github.com/ArtanisInc/StoW/pkg/strategy"
	"github.com/ArtanisInc/StoW/pkg/types"
)

// FieldModifiers holds field transformation modifiers
type FieldModifiers struct {
	Contains       bool
	StartsWith     bool
	EndsWith       bool
	HasAll         bool
	IsBase64       bool
	IsBase64Offset bool
	IsRegex        bool
	IsWindash      bool
	IsCIDR         bool
}

// ParseFieldModifiers extracts modifiers from field name
func ParseFieldModifiers(parts []string, value any) (FieldModifiers, any) {
	mods := FieldModifiers{}

	for _, part := range parts[1:] {
		switch strings.ToLower(part) {
		case "contains":
			mods.Contains = true
		case "startswith":
			mods.StartsWith = true
		case "endswith":
			mods.EndsWith = true
		case "all":
			mods.HasAll = true
		case "base64":
			mods.IsBase64 = true
		case "base64offset":
			mods.IsBase64Offset = true
		case "re":
			mods.IsRegex = true
		case "windash":
			mods.IsWindash = true
		case "cidr":
			mods.IsCIDR = true
		}
	}

	return mods, value
}

// BuildFieldValue constructs the final field value with modifiers
func BuildFieldValue(v string, mods FieldModifiers, fieldName string, product string) string {
	value := v

	// If this is already a regex (|re modifier), use it as-is
	if mods.IsRegex {
		// Add case-insensitive if needed
		if needsCaseInsensitive(fieldName, product) {
			value = "(?i)" + value
		}
		return value
	}

	// Convert Sigma wildcards to PCRE2 regex
	value = convertSigmaWildcardsToPCRE2(value)

	// Apply transformations based on modifiers
	if mods.Contains {
		// Already converted wildcards above
		value = value
	}
	if mods.StartsWith {
		value = "^" + value
	}
	if mods.EndsWith {
		value = value + "$"
	}

	// Add case-insensitive prefix if needed
	if needsCaseInsensitive(fieldName, product) {
		value = "(?i)" + value
	}

	return value
}

// convertSigmaWildcardsToPCRE2 converts Sigma wildcards (* and ?) to PCRE2 regex
// while escaping regex special characters
func convertSigmaWildcardsToPCRE2(value string) string {
	// If no wildcards, escape and return
	if !strings.ContainsAny(value, "*?") {
		return escapeRegexSpecialChars(value)
	}

	var result strings.Builder
	for i := 0; i < len(value); i++ {
		ch := value[i]
		switch ch {
		case '*':
			// Sigma * = zero or more characters = .* in PCRE2
			result.WriteString(".*")
		case '?':
			// Sigma ? = exactly one character = . in PCRE2
			result.WriteRune('.')
		case '\\':
			// Handle escape sequences
			if i+1 < len(value) {
				next := value[i+1]
				if next == '*' || next == '?' {
					// Escaped wildcard - treat as literal
					result.WriteRune('\\')
					result.WriteByte(next)
					i++ // skip next char
				} else {
					// Other backslash - escape it
					result.WriteString("\\\\")
				}
			} else {
				result.WriteString("\\\\")
			}
		default:
			// Escape regex special characters (except wildcards already handled)
			if isRegexSpecialChar(ch) {
				result.WriteRune('\\')
			}
			result.WriteByte(ch)
		}
	}
	return result.String()
}

// escapeRegexSpecialChars escapes PCRE2 special characters
func escapeRegexSpecialChars(value string) string {
	var result strings.Builder
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if isRegexSpecialChar(ch) {
			result.WriteRune('\\')
		}
		result.WriteByte(ch)
	}
	return result.String()
}

// isRegexSpecialChar checks if a character is a PCRE2 special character
func isRegexSpecialChar(ch byte) bool {
	// PCRE2 special characters that need escaping
	// Note: * and ? are handled separately as Sigma wildcards
	switch ch {
	case '.', '+', '^', '$', '(', ')', '[', ']', '{', '}', '|', '\\':
		return true
	}
	return false
}

// IsSimpleValue checks if a value is simple enough for exact field matching
func IsSimpleValue(v string) bool {
	// Check for regex/wildcard characters that require PCRE2
	return !strings.ContainsAny(v, "*?|()[]{}\\^$+.")
}

func needsCaseInsensitive(fieldName string, product string) bool {
	// Windows fields are case-insensitive
	if product == "windows" {
		return true
	}
	return false
}

// GetWazuhField returns the Wazuh field path for a Sigma field using strategy pattern
func GetWazuhField(fieldName string, sigma *types.SigmaRule, config *types.Config) string {
	strat := strategy.StrategyFactory(sigma, config)
	return strat.GetWazuhField(fieldName, sigma)
}

// SanitizeFieldName cleans up field names for use in Wazuh
func SanitizeFieldName(fieldName string) string {
	// Remove invalid characters
	fieldName = strings.ReplaceAll(fieldName, "|", "_")
	fieldName = strings.ReplaceAll(fieldName, " ", "_")
	return fieldName
}

// ExtractValuesFromRegex extracts literal values from regex patterns where possible
func ExtractValuesFromRegex(regexPattern string) []string {
	// Simple extraction for common patterns
	// This is a simplified version - full implementation would be more complex
	
	// Remove anchors
	pattern := strings.TrimPrefix(regexPattern, "^")
	pattern = strings.TrimSuffix(pattern, "$")
	
	// Check for simple alternation like (a|b|c)
	re := regexp.MustCompile(`^\(([^)]+)\)$`)
	if matches := re.FindStringSubmatch(pattern); matches != nil {
		return strings.Split(matches[1], "|")
	}
	
	return []string{pattern}
}
