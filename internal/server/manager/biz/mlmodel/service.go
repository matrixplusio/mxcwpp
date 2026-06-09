// Package mlmodel 实现 ML 模型分发管理 (复用 component 包体上传/CDN 通道)。
//
// 关键流程:
//
//  1. 安全工程师上传 ONNX/TFLite 模型 → component_packages (kind=ml-model)
//  2. 填模型元信息 → ml_model_specs (input/output shape / class label / train acc)
//  3. G5 模型验证闸门: ROC/影子模式跑通后 approved=true
//  4. 安全工程师创建订阅 → ml_model_subscriptions (host_id 或 label_selector)
//  5. Agent 心跳带 model_manifest → Manager 计算 diff → 返回拉取 URL
//  6. Agent 下载落 /opt/mxsec/agent/models/<spec_id>/<filename> + 校验 sha256
//  7. Agent 回报 → ml_model_deployment_status
//
// 选择复用 component 而非新建独立分发系统的原因:
//
//	component 已实现的能力: 多版本管理 / 包仓库 / sha256 校验 / RBAC / 软删除 / 推送任务
//	避免重复造轮子, 同时模型 + 插件 + 病毒库统一一套部署语义。
package mlmodel

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// Service 管理 ML 模型生命周期 + 订阅 + 部署状态。
type Service struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewService 构造。
func NewService(db *gorm.DB, logger *zap.Logger) *Service {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Service{db: db, logger: logger}
}

// RegisterSpec 给 (component_id, version_id) 附加模型元信息。
//
// 应在 component_packages 上传完成后调用。
func (s *Service) RegisterSpec(ctx context.Context, spec *model.MLModelSpec) (uint, error) {
	if spec == nil {
		return 0, errors.New("spec required")
	}
	if spec.ComponentID == 0 || spec.VersionID == 0 {
		return 0, errors.New("component_id and version_id required")
	}
	if spec.Kind == "" || spec.Framework == "" {
		return 0, errors.New("kind and framework required")
	}
	// 校验 component type
	var comp model.Component
	if err := s.db.WithContext(ctx).First(&comp, spec.ComponentID).Error; err != nil {
		return 0, fmt.Errorf("load component: %w", err)
	}
	// 不限制 component_type = ml-model;允许临时复用 scanner 等 component (e.g. virus-db sidecar 携带模型)。
	if err := s.db.WithContext(ctx).Create(spec).Error; err != nil {
		return 0, fmt.Errorf("create ml model spec: %w", err)
	}
	s.logger.Info("ml model spec registered",
		zap.Uint("id", spec.ID),
		zap.String("kind", spec.Kind),
		zap.String("framework", spec.Framework))
	return spec.ID, nil
}

// Approve 标记模型通过 G5 验证闸门, 允许下发。
func (s *Service) Approve(ctx context.Context, tenantID string, specID uint, approver string) error {
	res := s.db.WithContext(ctx).
		Model(&model.MLModelSpec{}).
		Where("tenant_id = ? AND id = ?", tenantID, specID).
		Updates(map[string]any{
			"approved":    true,
			"approved_by": approver,
			"approved_at": time.Now(),
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return errors.New("spec not found")
	}
	s.logger.Info("ml model approved",
		zap.Uint("spec_id", specID), zap.String("approver", approver))
	return nil
}

// Subscribe 创建一条订阅 (主机或 label 选择器)。
func (s *Service) Subscribe(ctx context.Context, sub *model.MLModelSubscription) (uint, error) {
	if sub.SpecID == 0 {
		return 0, errors.New("spec_id required")
	}
	if sub.HostID == "" && sub.LabelSelector == "" {
		return 0, errors.New("host_id or label_selector required")
	}
	// 必须 approved 后才能订阅 (G5 闸门)
	var spec model.MLModelSpec
	if err := s.db.WithContext(ctx).First(&spec, sub.SpecID).Error; err != nil {
		return 0, fmt.Errorf("load spec: %w", err)
	}
	if !spec.Approved {
		return 0, errors.New("spec not approved yet (G5 gate)")
	}
	sub.Enabled = true
	if err := s.db.WithContext(ctx).Create(sub).Error; err != nil {
		return 0, fmt.Errorf("create subscription: %w", err)
	}
	return sub.ID, nil
}

// ManifestForHost 返回某主机当前应当部署的模型清单 (Agent 心跳期间拉取)。
//
// 算法:
//
//  1. 找 host_id 直接订阅 (enabled=1, approved=1)
//  2. 找 label_selector 命中 (传入 hostLabels)
//  3. 去重 → 与现有 deployment_status diff → 返回新增/更新项
func (s *Service) ManifestForHost(ctx context.Context, tenantID, hostID string, hostLabels map[string]string) ([]ManifestEntry, error) {
	if hostID == "" {
		return nil, errors.New("host_id required")
	}
	var subs []model.MLModelSubscription
	if err := s.db.WithContext(ctx).
		Where("tenant_id = ? AND enabled = 1 AND (host_id = ? OR label_selector != '')", tenantID, hostID).
		Find(&subs).Error; err != nil {
		return nil, fmt.Errorf("query subscriptions: %w", err)
	}
	want := make(map[uint]bool)
	for _, sub := range subs {
		if sub.HostID == hostID {
			want[sub.SpecID] = true
			continue
		}
		if matchLabels(sub.LabelSelector, hostLabels) {
			want[sub.SpecID] = true
		}
	}
	if len(want) == 0 {
		return nil, nil
	}
	// 加载 specs + 包路径 (join component_packages)
	specIDs := make([]uint, 0, len(want))
	for id := range want {
		specIDs = append(specIDs, id)
	}
	var specs []model.MLModelSpec
	if err := s.db.WithContext(ctx).
		Where("id IN ? AND approved = 1", specIDs).
		Find(&specs).Error; err != nil {
		return nil, fmt.Errorf("load specs: %w", err)
	}
	// 查当前 deployment_status, 决定是否需要重新下载
	var status []model.MLModelDeploymentStatus
	_ = s.db.WithContext(ctx).
		Where("host_id = ? AND spec_id IN ?", hostID, specIDs).
		Find(&status).Error
	statusMap := make(map[uint]model.MLModelDeploymentStatus, len(status))
	for _, st := range status {
		statusMap[st.SpecID] = st
	}
	entries := make([]ManifestEntry, 0, len(specs))
	for _, spec := range specs {
		st, hasStatus := statusMap[spec.ID]
		if hasStatus && st.Status == "ready" {
			// 已就绪; 走 SHA256 比对决定是否升级
			continue
		}
		// 找该 version 的 amd64 二进制包 (后续多架构)
		var pkg model.ComponentPackage
		if err := s.db.WithContext(ctx).
			Where("version_id = ? AND enabled = 1", spec.VersionID).
			Order("id DESC").First(&pkg).Error; err != nil {
			s.logger.Warn("no package for spec", zap.Uint("spec_id", spec.ID), zap.Error(err))
			continue
		}
		entries = append(entries, ManifestEntry{
			SpecID:       spec.ID,
			Kind:         spec.Kind,
			Framework:    spec.Framework,
			FileName:     pkg.FileName,
			SHA256:       pkg.SHA256,
			Size:         pkg.FileSize,
			DownloadPath: fmt.Sprintf("/api/v1/components/packages/%d/download", pkg.ID),
			InputDim:     spec.InputDim,
			OutputDim:    spec.OutputDim,
		})
	}
	return entries, nil
}

// ReportStatus Agent 回报模型部署状态。
//
// 幂等: 同 (host_id, spec_id) upsert。
func (s *Service) ReportStatus(ctx context.Context, st *model.MLModelDeploymentStatus) error {
	if st.HostID == "" || st.SpecID == 0 {
		return errors.New("host_id and spec_id required")
	}
	st.UpdatedAt = model.LocalTime(time.Now())
	res := s.db.WithContext(ctx).
		Where("host_id = ? AND spec_id = ?", st.HostID, st.SpecID).
		Assign(map[string]any{
			"status":       st.Status,
			"sha256_local": st.SHA256Local,
			"error_msg":    st.ErrorMsg,
			"deployed_at":  st.DeployedAt,
			"updated_at":   st.UpdatedAt,
		}).
		FirstOrCreate(st)
	return res.Error
}

// ManifestEntry Agent 拉取的单条模型清单项。
type ManifestEntry struct {
	SpecID       uint   `json:"spec_id"`
	Kind         string `json:"kind"`
	Framework    string `json:"framework"`
	FileName     string `json:"file_name"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	DownloadPath string `json:"download_path"`
	InputDim     string `json:"input_dim"`
	OutputDim    string `json:"output_dim"`
}

// matchLabels 解析 "k=v,k2=v2" 全等匹配。
func matchLabels(selector string, labels map[string]string) bool {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return false
	}
	for _, term := range strings.Split(selector, ",") {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		kv := strings.SplitN(term, "=", 2)
		if len(kv) != 2 {
			return false
		}
		if labels[kv[0]] != kv[1] {
			return false
		}
	}
	return true
}
