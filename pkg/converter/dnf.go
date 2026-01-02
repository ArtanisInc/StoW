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

// BoolExpr represents a node in the boolean expression tree
type BoolExpr interface {
	ToDNF() [][]string
}

// Literal represents a selection name
type Literal struct {
	Value string
}

func (l Literal) ToDNF() [][]string {
	return [][]string{{l.Value}}
}

// And represents AND operation
type And struct {
	Left, Right BoolExpr
}

func (a And) ToDNF() [][]string {
	leftDNF := a.Left.ToDNF()
	rightDNF := a.Right.ToDNF()

	var result [][]string
	// Cartesian product of AND clauses
	for _, leftClause := range leftDNF {
		for _, rightClause := range rightDNF {
			combined := append([]string{}, leftClause...)
			combined = append(combined, rightClause...)
			result = append(result, combined)
		}
	}
	return result
}

// Or represents OR operation
type Or struct {
	Left, Right BoolExpr
}

func (o Or) ToDNF() [][]string {
	leftDNF := o.Left.ToDNF()
	rightDNF := o.Right.ToDNF()

	// Concatenate OR clauses
	result := append([][]string{}, leftDNF...)
	result = append(result, rightDNF...)
	return result
}

// Not represents NOT operation
type Not struct {
	Expr BoolExpr
}

func (n Not) ToDNF() [][]string {
	// For each clause in the DNF, prepend "not " to each literal
	dnf := n.Expr.ToDNF()
	var result [][]string

	for _, clause := range dnf {
		negatedClause := make([]string, len(clause))
		for i, literal := range clause {
			negatedClause[i] = "not " + literal
		}
		result = append(result, negatedClause)
	}

	return result
}

// parseExpression parses boolean expressions with precedence
func parseExpression(tokens []Token, pos int) (BoolExpr, int) {
	return parseOr(tokens, pos)
}

// parseOr handles OR operations (lowest precedence)
func parseOr(tokens []Token, pos int) (BoolExpr, int) {
	left, pos := parseAnd(tokens, pos)

	for pos < len(tokens) && tokens[pos].Type == "OR" {
		pos++ // skip OR
		right, newPos := parseAnd(tokens, pos)
		left = Or{Left: left, Right: right}
		pos = newPos
	}

	return left, pos
}

// parseAnd handles AND operations (higher precedence than OR)
func parseAnd(tokens []Token, pos int) (BoolExpr, int) {
	left, pos := parseNot(tokens, pos)

	for pos < len(tokens) && tokens[pos].Type == "AND" {
		pos++ // skip AND
		right, newPos := parseNot(tokens, pos)
		left = And{Left: left, Right: right}
		pos = newPos
	}

	return left, pos
}

// parseNot handles NOT operations (highest precedence)
func parseNot(tokens []Token, pos int) (BoolExpr, int) {
	if pos < len(tokens) && tokens[pos].Type == "NOT" {
		pos++ // skip NOT
		expr, pos := parsePrimary(tokens, pos)
		return Not{Expr: expr}, pos
	}

	return parsePrimary(tokens, pos)
}

// parsePrimary handles literals and parenthesized expressions
func parsePrimary(tokens []Token, pos int) (BoolExpr, int) {
	if pos >= len(tokens) {
		return Literal{Value: ""}, pos
	}

	if tokens[pos].Type == "LPAREN" {
		pos++ // skip (
		expr, pos := parseExpression(tokens, pos)
		if pos < len(tokens) && tokens[pos].Type == "RPAREN" {
			pos++ // skip )
		}
		return expr, pos
	}

	if tokens[pos].Type == "LITERAL" {
		return Literal{Value: tokens[pos].Value}, pos + 1
	}

	return Literal{Value: ""}, pos
}

// Parse converts tokens to DNF (Disjunctive Normal Form)
// Returns a list of AND clauses (each clause is a list of literals)
func Parse(tokens []Token) [][]string {
	if len(tokens) == 0 {
		return [][]string{{}}
	}

	expr, _ := parseExpression(tokens, 0)
	dnf := expr.ToDNF()

	// Filter out empty clauses and empty literals
	var result [][]string
	for _, clause := range dnf {
		var filteredClause []string
		for _, literal := range clause {
			if literal != "" {
				filteredClause = append(filteredClause, literal)
			}
		}
		if len(filteredClause) > 0 {
			result = append(result, filteredClause)
		}
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
