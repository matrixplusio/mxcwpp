package advisory

import (
	"context"
	"time"
)

// KylinSource 麒麟 (Kylin V10) Security Advisory 数据源。
//
// 注意：Kylin 官方无公开 API/feed，advisory 通过 https://kylinos.cn/support/ 网站发布。
// 完整解析需爬虫 + 解析 PDF/HTML，或对接商业镜像源。
//
// 当前阶段：stub，仅占位让 Coordinator 识别 kylin OS family。
// 完整实施待对接商业镜像源后(P3-1c-2)。
type KylinSource struct{}

// NewKylinSource 构造。
func NewKylinSource() *KylinSource { return &KylinSource{} }

// Name 实现 Source。
func (s *KylinSource) Name() string { return "kylin-sa" }

// Confidence 实现 Source：Kylin 官方权威 = high。
func (s *KylinSource) Confidence() Confidence { return ConfidenceHigh }

// Fetch 当前阶段返回空，待对接商业镜像源后实施。
func (s *KylinSource) Fetch(_ context.Context, _ time.Time) ([]*Advisory, error) {
	return nil, nil
}

// UOSSource 统信 UOS Security Advisory 数据源。
//
// UOS 基于 Debian 衍生，advisory 通过 https://uniontech.com/support/ 发布。
// 当前 stub，待对接后实施。
type UOSSource struct{}

// NewUOSSource 构造。
func NewUOSSource() *UOSSource { return &UOSSource{} }

// Name 实现 Source。
func (s *UOSSource) Name() string { return "uos-sa" }

// Confidence 实现 Source：UOS 官方权威 = high。
func (s *UOSSource) Confidence() Confidence { return ConfidenceHigh }

// Fetch 当前阶段返回空，待对接商业镜像源后实施。
func (s *UOSSource) Fetch(_ context.Context, _ time.Time) ([]*Advisory, error) {
	return nil, nil
}
