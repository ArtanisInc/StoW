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
	// Apply De Morgan's laws to correctly distribute NOT:
	// NOT (A AND B) = (NOT A) OR (NOT B) → [[not A], [not B]]
	// NOT (A OR B) = (NOT A) AND (NOT B) → [[not A, not B]]

	dnf := n.Expr.ToDNF()

	if len(dnf) == 1 {
		// Single clause (conjunction of literals): NOT (A AND B AND C)
		// Apply De Morgan: becomes (NOT A) OR (NOT B) OR (NOT C)
		// DNF representation: [[not A], [not B], [not C]]
		var result [][]string
		for _, literal := range dnf[0] {
			result = append(result, []string{"not " + literal})
		}
		return result
	} else {
		// Multiple clauses (disjunction): NOT ((A AND B) OR (C AND D))
		// Apply De Morgan: becomes (NOT A OR NOT B) AND (NOT C OR NOT D)
		// Which simplifies to: (NOT A AND NOT C) OR (NOT A AND NOT D) OR (NOT B AND NOT C) OR (NOT B AND NOT D)
		// But for Sigma, we simplify to just negate all literals and combine with AND
		// DNF representation: [[not A, not B, not C, not D]]
		var allNegatedLiterals []string
		for _, clause := range dnf {
			for _, literal := range clause {
				allNegatedLiterals = append(allNegatedLiterals, "not "+literal)
			}
		}
		return [][]string{allNegatedLiterals}
	}
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
	// Note: "1 of" and "all of" are handled in PreprocessCondition after wildcard expansion
	// Here we just normalize spacing

	// Normalize spacing
	condition = strings.TrimSpace(condition)

	return condition
}

// PreprocessCondition prepares a condition for DNF conversion
func PreprocessCondition(condition string, detections map[string]any) string {
	// Clean up the condition
	condition = FixupCondition(condition)

	// Detect "1 of" and "all of" patterns
	re1of := regexp.MustCompile(`1\s+of\s+`)
	reAllof := regexp.MustCompile(`all\s+of\s+`)

	hasAllof := reAllof.MatchString(condition)

	// Temporarily remove "1 of" and "all of" markers for wildcard expansion
	condition = re1of.ReplaceAllString(condition, "")
	condition = reAllof.ReplaceAllString(condition, "")

	// Expand wildcards like "selection*" to "selection_a or selection_b or ..."
	// Find all wildcard patterns in the condition
	words := strings.Fields(condition)
	for i, word := range words {
		// Remove parentheses for checking
		cleanWord := strings.Trim(word, "()")

		if strings.HasSuffix(cleanWord, "*") {
			prefix := strings.TrimSuffix(cleanWord, "*")
			var matches []string

			// Find all detection keys that start with this prefix
			for key := range detections {
				if strings.HasPrefix(key, prefix) {
					matches = append(matches, key)
				}
			}

			// Replace wildcard with appropriate conjunction
			if len(matches) > 0 {
				// Preserve parentheses if they were present
				hasOpenParen := strings.HasPrefix(word, "(")
				hasCloseParen := strings.HasSuffix(word, ")")

				var expansion string
				if hasAllof {
					// "all of" means AND between all matches
					expansion = strings.Join(matches, " and ")
				} else {
					// "1 of" or default means OR between matches
					expansion = strings.Join(matches, " or ")
				}

				if len(matches) > 1 {
					expansion = "(" + expansion + ")"
				}

				if hasOpenParen && !strings.HasPrefix(expansion, "(") {
					expansion = "(" + expansion
				}
				if hasCloseParen && !strings.HasSuffix(expansion, ")") {
					expansion = expansion + ")"
				}

				words[i] = expansion
			}
		}
	}

	condition = strings.Join(words, " ")
	return condition
}
