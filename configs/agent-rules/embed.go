// Package agentrules 提供内嵌的 Agent YAML 检测规则
package agentrules

import "embed"

//go:embed MXEDR-*.yaml
var BuiltinRules embed.FS
