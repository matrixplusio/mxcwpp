//go:build !sonic && !gojson

package jsonx

import (
	"encoding/json"
	"io"
)

// Marshal 兼容 encoding/json.
func Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

// MarshalIndent 兼容 encoding/json.
func MarshalIndent(v any, prefix, indent string) ([]byte, error) {
	return json.MarshalIndent(v, prefix, indent)
}

// Unmarshal 兼容 encoding/json.
func Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

// NewEncoder 兼容 encoding/json.
func NewEncoder(w io.Writer) Encoder {
	return json.NewEncoder(w)
}

// NewDecoder 兼容 encoding/json.
func NewDecoder(r io.Reader) Decoder {
	return json.NewDecoder(r)
}

// Encoder 抽象, 与 json.Encoder 兼容.
type Encoder interface {
	Encode(v any) error
	SetIndent(prefix, indent string)
}

// Decoder 抽象.
type Decoder interface {
	Decode(v any) error
	UseNumber()
	DisallowUnknownFields()
}

// Backend 返回当前实现名 (供 /metrics / log 报告).
func Backend() string { return "stdlib" }
