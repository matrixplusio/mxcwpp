//go:build sonic && amd64

// sonic 仅 amd64 支持 (依赖 AVX2 汇编).
//
// 启用方式: go build -tags sonic ./...
//
// 启用前需 go get -u github.com/bytedance/sonic.

package jsonx

import (
	"io"

	"github.com/bytedance/sonic"
)

var api = sonic.ConfigDefault

func Marshal(v any) ([]byte, error) { return api.Marshal(v) }
func MarshalIndent(v any, prefix, indent string) ([]byte, error) {
	return sonic.MarshalIndent(v, prefix, indent)
}
func Unmarshal(data []byte, v any) error { return api.Unmarshal(data, v) }
func NewEncoder(w io.Writer) Encoder     { return api.NewEncoder(w) }
func NewDecoder(r io.Reader) Decoder     { return api.NewDecoder(r) }

type Encoder interface {
	Encode(v any) error
	SetIndent(prefix, indent string)
}

type Decoder interface {
	Decode(v any) error
	UseNumber()
	DisallowUnknownFields()
}

func Backend() string { return "sonic" }
