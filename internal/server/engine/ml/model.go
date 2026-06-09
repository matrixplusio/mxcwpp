// Package ml 是 Engine 的本地机器学习推理抽象。
//
// 设计文档: docs/ml-models.md
//
// 当前形态 (Sprint 3 PR51):
//   - 定义统一 Model interface (Predict + Name + Version)
//   - 提供 Go-native IForest 实现 (无 CGO 依赖,直接 build 可用)
//   - 提供 Registry 用于按 name 索引
//
// 后续 PR (留 TODO):
//   - ONNX Runtime Go binding 适配 (github.com/yalue/onnxruntime_go)
//   - LightGBM / XGBoost ONNX 模型
//   - MiniLM Embedding 模型
//   - 模型热加载 + 灰度版本
package ml

import (
	"fmt"
	"sync"
)

// Model 是单个 ML 模型的统一抽象。
//
// 实现方包括: IForestModel (Go native), ONNXModel (PR 后续).
// Predict 应是 stateless 的; Model 内部可缓存训练参数。
type Model interface {
	// Name 模型唯一名 (如 "iforest_host_metrics" / "lightgbm_elf")。
	Name() string

	// Version 模型版本 (语义化 + 训练日期)。
	Version() string

	// Predict 对单条样本做推理。
	//
	// features 是模型期望的特征向量;
	// 返回 score 与可选 label (二分类时 0/1, 异常检测时浮点分数)。
	Predict(features []float64) (score float64, label string, err error)

	// FeatureNames 返回特征顺序 (调用方按此顺序构造 features)。
	FeatureNames() []string
}

// Registry 是 model 注册表。
type Registry struct {
	mu     sync.RWMutex
	models map[string]Model
}

// NewRegistry 构造空 registry。
func NewRegistry() *Registry {
	return &Registry{models: make(map[string]Model)}
}

// Register 注册 model。
func (r *Registry) Register(m Model) error {
	if m == nil {
		return fmt.Errorf("ml: model must not be nil")
	}
	name := m.Name()
	if name == "" {
		return fmt.Errorf("ml: Name() must not be empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.models[name]; ok {
		return fmt.Errorf("ml: %q already registered", name)
	}
	r.models[name] = m
	return nil
}

// Get 按 name 取 model。
func (r *Registry) Get(name string) (Model, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.models[name]
	return m, ok
}

// Names 列出所有 model 名。
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.models))
	for n := range r.models {
		out = append(out, n)
	}
	return out
}
