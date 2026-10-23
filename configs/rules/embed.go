// Package rules 提供内置检测规则的嵌入数据
package rules

import _ "embed"

//go:embed builtin-rules.yaml
var BuiltinRulesYAML []byte
