package advisory

import (
	"context"
	"time"
)

// OpenEulerSource openEuler Security Advisory 数据源。
//
// 上游 CVRF 1.2 XML feed:
//   - index: https://repo.openeuler.org/security/data/cvrf/index.txt
//   - detail: https://repo.openeuler.org/security/data/cvrf/{yyyy}/cvrf-openEuler-SA-{yyyy}-{nnnn}.xml
//
// 当前阶段：stub 实现，仅占位让 Coordinator 识别 openeuler OS family。
// 完整 CVRF XML 解析待真 openEuler 主机上线后实施(P3-1a-2)。
type OpenEulerSource struct{}

// NewOpenEulerSource 构造。
func NewOpenEulerSource() *OpenEulerSource { return &OpenEulerSource{} }

// Name 实现 Source。
func (s *OpenEulerSource) Name() string { return "openeuler-sa" }

// Confidence 实现 Source：openEuler 官方权威 = high。
func (s *OpenEulerSource) Confidence() Confidence { return ConfidenceHigh }

// Fetch 当前阶段返回空，待真 openEuler 主机入网后实施完整 CVRF 解析。
func (s *OpenEulerSource) Fetch(_ context.Context, _ time.Time) ([]*Advisory, error) {
	return nil, nil
}
