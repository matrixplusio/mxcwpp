package advisory

import (
	"context"
	"time"
)

// AnolisSource 龙蜥 (Anolis OS) ANSA Security Advisory 数据源。
//
// 上游 API:
//   - https://anas.openanolis.org/api/cves (按 CVE 查)
//   - https://anas.openanolis.org/api/sas (按 ANSA 查)
//
// 当前阶段：stub，仅占位让 Coordinator 识别 anolis OS family。
// 完整 API 解析待真 Anolis 主机入网后实施(P3-1b-2)。
type AnolisSource struct{}

// NewAnolisSource 构造。
func NewAnolisSource() *AnolisSource { return &AnolisSource{} }

// Name 实现 Source。
func (s *AnolisSource) Name() string { return "anolis-ansa" }

// Confidence 实现 Source：Anolis 官方权威 = high。
func (s *AnolisSource) Confidence() Confidence { return ConfidenceHigh }

// Fetch 当前阶段返回空，待真 Anolis 主机入网后实施 ANSA API 解析。
func (s *AnolisSource) Fetch(_ context.Context, _ time.Time) ([]*Advisory, error) {
	return nil, nil
}
