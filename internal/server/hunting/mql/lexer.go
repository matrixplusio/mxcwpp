package mql

import (
	"fmt"
	"strings"
	"unicode"
)

// TokenType is the type of a lexer token.
type TokenType int

const (
	TokEOF    TokenType = iota
	TokPipe             // |
	TokIdent            // field name or keyword
	TokString           // "quoted string"
	TokNumber           // integer or float
	TokEq               // ==
	TokNeq              // !=
	TokGt               // >
	TokGte              // >=
	TokLt               // <
	TokLte              // <=
	TokLParen           // (
	TokRParen           // )
	TokComma            // ,
	TokMinus            // -
)

// Token is a single lexer token.
type Token struct {
	Type TokenType
	Val  string
	Pos  int // byte offset in input
}

// Lexer tokenizes MQL input.
type Lexer struct {
	input  string
	pos    int
	tokens []Token
}

// Lex tokenizes the input string into a token slice.
func Lex(input string) ([]Token, error) {
	l := &Lexer{input: input}
	if err := l.scan(); err != nil {
		return nil, err
	}
	return l.tokens, nil
}

func (l *Lexer) scan() error {
	for l.pos < len(l.input) {
		l.skipWhitespace()
		if l.pos >= len(l.input) {
			break
		}

		ch := l.input[l.pos]

		switch {
		case ch == '|':
			l.emit(TokPipe, "|")
		case ch == '(':
			l.emit(TokLParen, "(")
		case ch == ')':
			l.emit(TokRParen, ")")
		case ch == ',':
			l.emit(TokComma, ",")
		case ch == '-':
			l.emit(TokMinus, "-")
		case ch == '=' && l.peek() == '=':
			l.emitN(TokEq, "==", 2)
		case ch == '!' && l.peek() == '=':
			l.emitN(TokNeq, "!=", 2)
		case ch == '>' && l.peek() == '=':
			l.emitN(TokGte, ">=", 2)
		case ch == '>':
			l.emit(TokGt, ">")
		case ch == '<' && l.peek() == '=':
			l.emitN(TokLte, "<=", 2)
		case ch == '<':
			l.emit(TokLt, "<")
		case ch == '"' || ch == '\'':
			tok, err := l.scanString(ch)
			if err != nil {
				return err
			}
			l.tokens = append(l.tokens, tok)
		case unicode.IsDigit(rune(ch)):
			l.scanNumber()
		case unicode.IsLetter(rune(ch)) || ch == '_':
			l.scanIdent()
		default:
			return fmt.Errorf("unexpected character %q at position %d", ch, l.pos)
		}
	}

	l.tokens = append(l.tokens, Token{Type: TokEOF, Pos: l.pos})
	return nil
}

func (l *Lexer) skipWhitespace() {
	for l.pos < len(l.input) && (l.input[l.pos] == ' ' || l.input[l.pos] == '\t' || l.input[l.pos] == '\n' || l.input[l.pos] == '\r') {
		l.pos++
	}
}

func (l *Lexer) peek() byte {
	if l.pos+1 < len(l.input) {
		return l.input[l.pos+1]
	}
	return 0
}

func (l *Lexer) emit(typ TokenType, val string) {
	l.tokens = append(l.tokens, Token{Type: typ, Val: val, Pos: l.pos})
	l.pos++
}

func (l *Lexer) emitN(typ TokenType, val string, n int) {
	l.tokens = append(l.tokens, Token{Type: typ, Val: val, Pos: l.pos})
	l.pos += n
}

func (l *Lexer) scanString(quote byte) (Token, error) {
	start := l.pos
	l.pos++ // skip opening quote
	var sb strings.Builder
	for l.pos < len(l.input) {
		ch := l.input[l.pos]
		if ch == '\\' && l.pos+1 < len(l.input) {
			l.pos++
			sb.WriteByte(l.input[l.pos])
			l.pos++
			continue
		}
		if ch == quote {
			l.pos++ // skip closing quote
			return Token{Type: TokString, Val: sb.String(), Pos: start}, nil
		}
		sb.WriteByte(ch)
		l.pos++
	}
	return Token{}, fmt.Errorf("unterminated string at position %d", start)
}

func (l *Lexer) scanNumber() {
	start := l.pos
	for l.pos < len(l.input) && (unicode.IsDigit(rune(l.input[l.pos])) || l.input[l.pos] == '.') {
		l.pos++
	}
	// Check for duration suffix (h, m, s, d).
	if l.pos < len(l.input) {
		ch := l.input[l.pos]
		if ch == 'h' || ch == 'm' || ch == 's' || ch == 'd' {
			l.pos++
		}
	}
	l.tokens = append(l.tokens, Token{Type: TokNumber, Val: l.input[start:l.pos], Pos: start})
}

func (l *Lexer) scanIdent() {
	start := l.pos
	for l.pos < len(l.input) && (unicode.IsLetter(rune(l.input[l.pos])) || unicode.IsDigit(rune(l.input[l.pos])) || l.input[l.pos] == '_') {
		l.pos++
	}
	l.tokens = append(l.tokens, Token{Type: TokIdent, Val: l.input[start:l.pos], Pos: start})
}
