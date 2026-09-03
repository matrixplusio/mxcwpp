package mql

import (
	"fmt"
	"strconv"
	"strings"
)

// Parser is a recursive descent parser for MQL.
type Parser struct {
	tokens []Token
	pos    int
}

// Parse parses an MQL query string into an AST.
func Parse(input string) (*Query, error) {
	tokens, err := Lex(input)
	if err != nil {
		return nil, fmt.Errorf("lexer: %w", err)
	}

	p := &Parser{tokens: tokens}
	return p.parseQuery()
}

func (p *Parser) parseQuery() (*Query, error) {
	q := &Query{}

	// Expect: search <source>
	if err := p.expectIdent("search"); err != nil {
		return nil, err
	}
	src := p.current()
	if src.Type != TokIdent {
		return nil, p.errorf("expected source name after 'search', got %q", src.Val)
	}
	q.Source = src.Val
	p.advance()

	// Parse pipe stages.
	for p.match(TokPipe) {
		stage := p.current()
		if stage.Type != TokIdent {
			return nil, p.errorf("expected stage keyword after '|', got %q", stage.Val)
		}

		switch strings.ToLower(stage.Val) {
		case "where":
			p.advance()
			cond, err := p.parseCondition()
			if err != nil {
				return nil, err
			}
			if q.Stats != nil {
				q.Having = append(q.Having, cond)
			} else {
				q.Wheres = append(q.Wheres, cond)
			}
		case "stats":
			p.advance()
			stats, err := p.parseStats()
			if err != nil {
				return nil, err
			}
			q.Stats = stats
		case "sort":
			p.advance()
			sort, err := p.parseSort()
			if err != nil {
				return nil, err
			}
			q.Sort = append(q.Sort, sort...)
		case "limit":
			p.advance()
			tok := p.current()
			if tok.Type != TokNumber {
				return nil, p.errorf("expected number after 'limit', got %q", tok.Val)
			}
			n, err := strconv.Atoi(tok.Val)
			if err != nil {
				return nil, p.errorf("invalid limit: %q", tok.Val)
			}
			q.Limit = n
			p.advance()
		default:
			return nil, p.errorf("unknown stage %q", stage.Val)
		}
	}

	if p.current().Type != TokEOF {
		return nil, p.errorf("unexpected token %q", p.current().Val)
	}

	return q, nil
}

func (p *Parser) parseCondition() (Condition, error) {
	var cond Condition

	// Check for NOT prefix.
	if p.current().Type == TokIdent && strings.ToUpper(p.current().Val) == "NOT" {
		cond.Negate = true
		p.advance()
	}

	// Check if this is a function call: func_name(field)
	if p.current().Type == TokIdent && p.peekType() == TokLParen {
		funcName := p.current().Val
		p.advance() // skip func name
		p.advance() // skip (
		if p.current().Type == TokIdent {
			cond.Field = p.current().Val
			p.advance()
		}
		if p.current().Type != TokRParen {
			return cond, p.errorf("expected ')' after function argument")
		}
		p.advance()
		cond.Function = funcName
		cond.Op = OpEq
		cond.Value = "true"
		return cond, nil
	}

	// Field name.
	if p.current().Type != TokIdent {
		return cond, p.errorf("expected field name, got %q", p.current().Val)
	}
	cond.Field = p.current().Val
	p.advance()

	// Operator — check for keyword operators first.
	tok := p.current()
	switch {
	case tok.Type == TokEq:
		cond.Op = OpEq
		p.advance()
	case tok.Type == TokNeq:
		cond.Op = OpNeq
		p.advance()
	case tok.Type == TokGt:
		cond.Op = OpGt
		p.advance()
	case tok.Type == TokGte:
		cond.Op = OpGte
		p.advance()
	case tok.Type == TokLt:
		cond.Op = OpLt
		p.advance()
	case tok.Type == TokLte:
		cond.Op = OpLte
		p.advance()
	case tok.Type == TokIdent && strings.ToLower(tok.Val) == "contains":
		cond.Op = OpContains
		p.advance()
	case tok.Type == TokIdent && strings.ToLower(tok.Val) == "startswith":
		cond.Op = OpStartsWith
		p.advance()
	case tok.Type == TokIdent && strings.ToLower(tok.Val) == "endswith":
		cond.Op = OpEndsWith
		p.advance()
	case tok.Type == TokIdent && strings.ToLower(tok.Val) == "matches":
		cond.Op = OpMatches
		p.advance()
	case tok.Type == TokIdent && strings.ToLower(tok.Val) == "in":
		cond.Op = OpIn
		p.advance()
	default:
		return cond, p.errorf("expected operator, got %q", tok.Val)
	}

	// Value — handle special cases.
	val, err := p.parseValue()
	if err != nil {
		return cond, err
	}
	cond.Value = val

	return cond, nil
}

func (p *Parser) parseValue() (string, error) {
	tok := p.current()

	switch tok.Type {
	case TokString:
		p.advance()
		return tok.Val, nil
	case TokNumber:
		p.advance()
		return tok.Val, nil
	case TokIdent:
		// Handle now() - duration expressions.
		if strings.ToLower(tok.Val) == "now" {
			p.advance()
			if p.current().Type == TokLParen {
				p.advance() // (
				if p.current().Type != TokRParen {
					return "", p.errorf("expected ')' after now(")
				}
				p.advance() // )
				// Check for - duration.
				if p.current().Type == TokMinus {
					p.advance()
					dur := p.current()
					if dur.Type != TokNumber {
						return "", p.errorf("expected duration after now() -")
					}
					p.advance()
					return "now()-" + dur.Val, nil
				}
				return "now()", nil
			}
		}
		// Handle in (...) list — comma-separated strings/numbers.
		if tok.Type == TokLParen {
			return p.parseList()
		}
		p.advance()
		return tok.Val, nil
	case TokLParen:
		return p.parseList()
	default:
		return "", p.errorf("expected value, got %q", tok.Val)
	}
}

func (p *Parser) parseList() (string, error) {
	if p.current().Type != TokLParen {
		return "", p.errorf("expected '(' for list")
	}
	p.advance()

	var items []string
	for p.current().Type != TokRParen {
		if len(items) > 0 {
			if p.current().Type != TokComma {
				return "", p.errorf("expected ',' in list")
			}
			p.advance()
		}
		tok := p.current()
		if tok.Type == TokString || tok.Type == TokNumber || tok.Type == TokIdent {
			items = append(items, tok.Val)
			p.advance()
		} else {
			return "", p.errorf("unexpected token in list: %q", tok.Val)
		}
	}
	p.advance() // skip )
	return strings.Join(items, ","), nil
}

func (p *Parser) parseStats() (*StatsClause, error) {
	sc := &StatsClause{}

	// Parse aggregation functions: func(field) as alias, ...
	for {
		agg, err := p.parseAggregation()
		if err != nil {
			return nil, err
		}
		sc.Aggregations = append(sc.Aggregations, agg)
		if p.current().Type != TokComma {
			break
		}
		p.advance() // skip comma
	}

	// Check for "by" clause.
	if p.current().Type == TokIdent && strings.ToLower(p.current().Val) == "by" {
		p.advance()
		for {
			if p.current().Type != TokIdent {
				return nil, p.errorf("expected field name in GROUP BY")
			}
			sc.GroupBy = append(sc.GroupBy, p.current().Val)
			p.advance()
			if p.current().Type != TokComma {
				break
			}
			p.advance()
		}
	}

	return sc, nil
}

func (p *Parser) parseAggregation() (Aggregation, error) {
	var agg Aggregation

	if p.current().Type != TokIdent {
		return agg, p.errorf("expected aggregation function name")
	}
	agg.Func = strings.ToLower(p.current().Val)
	p.advance()

	// Expect (field) or ().
	if p.current().Type != TokLParen {
		return agg, p.errorf("expected '(' after function name")
	}
	p.advance()

	if p.current().Type != TokRParen {
		if p.current().Type != TokIdent {
			return agg, p.errorf("expected field name in aggregation")
		}
		agg.Field = p.current().Val
		p.advance()
	}

	if p.current().Type != TokRParen {
		return agg, p.errorf("expected ')' after aggregation argument")
	}
	p.advance()

	// Optional "as alias".
	if p.current().Type == TokIdent && strings.ToLower(p.current().Val) == "as" {
		p.advance()
		if p.current().Type != TokIdent {
			return agg, p.errorf("expected alias after 'as'")
		}
		agg.Alias = p.current().Val
		p.advance()
	} else {
		// Auto-generate alias.
		if agg.Field != "" {
			agg.Alias = agg.Func + "_" + agg.Field
		} else {
			agg.Alias = agg.Func
		}
	}

	return agg, nil
}

func (p *Parser) parseSort() ([]SortField, error) {
	var fields []SortField
	for {
		if p.current().Type != TokIdent {
			return nil, p.errorf("expected field name in sort")
		}
		sf := SortField{Field: p.current().Val}
		p.advance()

		// Optional asc/desc.
		if p.current().Type == TokIdent {
			switch strings.ToLower(p.current().Val) {
			case "desc":
				sf.Desc = true
				p.advance()
			case "asc":
				p.advance()
			}
		}
		fields = append(fields, sf)

		if p.current().Type != TokComma {
			break
		}
		p.advance()
	}
	return fields, nil
}

// Helper methods.

func (p *Parser) current() Token {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return Token{Type: TokEOF}
}

func (p *Parser) advance() {
	if p.pos < len(p.tokens) {
		p.pos++
	}
}

func (p *Parser) match(typ TokenType) bool {
	if p.current().Type == typ {
		p.advance()
		return true
	}
	return false
}

func (p *Parser) peekType() TokenType {
	if p.pos+1 < len(p.tokens) {
		return p.tokens[p.pos+1].Type
	}
	return TokEOF
}

func (p *Parser) expectIdent(keyword string) error {
	tok := p.current()
	if tok.Type != TokIdent || strings.ToLower(tok.Val) != keyword {
		return p.errorf("expected %q, got %q", keyword, tok.Val)
	}
	p.advance()
	return nil
}

func (p *Parser) errorf(format string, args ...any) error {
	pos := 0
	if p.pos < len(p.tokens) {
		pos = p.tokens[p.pos].Pos
	}
	return fmt.Errorf("mql parse error at position %d: "+format, append([]any{pos}, args...)...)
}
