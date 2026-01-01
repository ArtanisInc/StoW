package converter

import (
	"regexp"
	"strings"
)

// Token represents a token in a boolean expression
type Token struct {
	Type  string // "AND", "OR", "NOT", "LPAREN", "RPAREN", "LITERAL"
	Value string
}

// Tokenize converts a condition string into tokens
func Tokenize(expr string) []Token {
	var tokens []Token
	expr = strings.TrimSpace(expr)

	// Simple tokenizer
	parts := strings.Fields(expr)
	for _, part := range parts {
		switch strings.ToLower(part) {
		case "and":
			tokens = append(tokens, Token{Type: "AND", Value: "and"})
		case "or":
			tokens = append(tokens, Token{Type: "OR", Value: "or"})
		case "not":
			tokens = append(tokens, Token{Type: "NOT", Value: "not"})
		case "(":
			tokens = append(tokens, Token{Type: "LPAREN", Value: "("})
		case ")":
			tokens = append(tokens, Token{Type: "RPAREN", Value: ")"})
		default:
			// Handle parentheses attached to identifiers
			part = strings.ReplaceAll(part, "(", " ( ")
			part = strings.ReplaceAll(part, ")", " ) ")
			subparts := strings.Fields(part)
			for _, sub := range subparts {
				if sub == "(" {
					tokens = append(tokens, Token{Type: "LPAREN", Value: "("})
				} else if sub == ")" {
					tokens = append(tokens, Token{Type: "RPAREN", Value: ")"})
				} else {
					tokens = append(tokens, Token{Type: "LITERAL", Value: sub})
				}
			}
		}
	}

	return tokens
}

// Parse converts tokens to DNF (Disjunctive Normal Form)
// Returns a list of AND clauses (each clause is a list of literals)
func Parse(tokens []Token) [][]string {
	// Simplified parser - returns DNF sets
	// In reality this would be more complex

	var result [][]string
	var current []string

	for _, token := range tokens {
		if token.Type == "LITERAL" {
			current = append(current, token.Value)
		} else if token.Type == "OR" {
			if len(current) > 0 {
				result = append(result, current)
				current = []string{}
			}
		}
	}

	if len(current) > 0 {
		result = append(result, current)
	}

	// If no result, return single empty set
	if len(result) == 0 {
		result = [][]string{{}}
	}

	return result
}

// ConvertToDNF converts a boolean expression to Disjunctive Normal Form
func ConvertToDNF(expr string) [][]string {
	tokens := Tokenize(expr)
	return Parse(tokens)
}

// FixupCondition cleans and normalizes a condition string
func FixupCondition(condition string) string {
	// Replace 1 of with "or"
	re := regexp.MustCompile(`1\s+of\s+`)
	condition = re.ReplaceAllString(condition, "")

	// Normalize spacing
	condition = strings.TrimSpace(condition)

	return condition
}

// PreprocessCondition prepares a condition for DNF conversion
func PreprocessCondition(condition string, detections map[string]any) string {
	// Clean up the condition
	condition = FixupCondition(condition)

	// Expand wildcards like selection*
	for key := range detections {
		if strings.Contains(condition, key+"*") {
			// Replace wildcard with actual key
			condition = strings.ReplaceAll(condition, key+"*", key)
		}
	}

	return condition
}
