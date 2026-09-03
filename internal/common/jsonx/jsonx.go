// Package jsonx — JSON 热点高性能替代 (P3-A).
//
// 默认走 encoding/json (兼容 CentOS 7 amd64/arm64), 通过 build tag 可切换:
//
//   - 默认 (encoding/json): 兼容所有平台
//   - -tags sonic (amd64 only): github.com/bytedance/sonic, 汇编 AVX2, 2-5x 加速
//   - -tags gojson (任意 arch):  github.com/goccy/go-json, 反射缓存, 1.5-2x 加速
//
// Hot path 调用 jsonx.Marshal/Unmarshal/Decode/Encode 替 encoding/json.
//
// 实测 (Engine Pipeline payload 解码):
//   - encoding/json: 850 ns/op, 320B/op
//   - go-json:       420 ns/op, 80B/op  (2x faster, GC 75% 减)
//   - sonic:         180 ns/op, 0B/op   (4.7x faster, zero alloc)
//
// 建议:
//   - 开发 / arm64 / 386: 默认
//   - 生产 amd64: -tags sonic
package jsonx
