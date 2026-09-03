package advisory

import (
	"context"
	"time"
)

// CentOSSource CentOS Stream advisory 别名（实际 fetch 走 RHSA，因为 CentOS Stream 与 RHEL 同源）。
//
// 不重复拉数据 — 仅作 UI 标识让 admin 知道 CentOS 已覆盖。
// Fetch 返回空，coordinator 会写 last_count=0 + last_status=success（无错误）。
type CentOSSource struct{}

// NewCentOSSource 构造。
func NewCentOSSource() *CentOSSource { return &CentOSSource{} }

// Name 实现 Source。
func (c *CentOSSource) Name() string { return "centos" }

// Confidence 实现 Source。
func (c *CentOSSource) Confidence() Confidence { return ConfidenceHigh }

// Fetch 不实际拉数据：CentOS Stream 9/10 与 RHEL 同源，启用 RHSA 即覆盖。
func (c *CentOSSource) Fetch(_ context.Context, _ time.Time) ([]*Advisory, error) {
	return nil, nil
}
