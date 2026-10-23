//go:build gojson && !sonic

// gojson 跨架构 fallback (CentOS 7 + arm64 + 386 都可).
//
// 启用方式: go build -tags gojson ./...
//
// 启用前需 go get -u github.com/goccy/go-json.

package jsonx

import (
	"io"

	gojson "github.com/goccy/go-json"
)

func Marshal(v any) ([]byte, error) { return gojson.Marshal(v) }
func MarshalIndent(v any, prefix, indent string) ([]byte, error) {
	return gojson.MarshalIndent(v, prefix, indent)
}
func Unmarshal(data []byte, v any) error { return gojson.Unmarshal(data, v) }
func NewEncoder(w io.Writer) Encoder     { return gojson.NewEncoder(w) }
func NewDecoder(r io.Reader) Decoder     { return gojson.NewDecoder(r) }

type Encoder interface {
	Encode(v any) error
	SetIndent(prefix, indent string)
}

type Decoder interface {
	Decode(v any) error
	UseNumber()
	DisallowUnknownFields()
}

func Backend() string { return "gojson" }
