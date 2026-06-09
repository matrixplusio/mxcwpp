package ml

import (
	"math"
	"math/rand"
	"sync"
)

// IForestModel 是简化的 Isolation Forest Go-native 实现。
//
// 适用于主机行为异常基线 (cpu/mem/io 等 metrics 维度).
// 训练接收一批正常样本 (assume mostly normal),
// Predict 输出异常分数 [0, 1] (越大越异常).
//
// 限制 (vs 完整 sklearn IForest):
//   - 用简单的随机 split 替代真实 sklearn-style sub-sampling
//   - 不支持 contamination 自动校准 (留 ONNX PR)
//   - 单进程内存训练,大数据集应走 sklearn->ONNX 路径
type IForestModel struct {
	name     string
	version  string
	features []string
	numTrees int
	maxDepth int

	mu    sync.RWMutex
	trees []*iTree
}

// IForestConfig 是 IForest 配置。
type IForestConfig struct {
	Name     string
	Version  string
	Features []string
	NumTrees int // 默认 50
	MaxDepth int // 默认 8
}

// NewIForestModel 构造一个未训练的 IForestModel。
func NewIForestModel(cfg IForestConfig) *IForestModel {
	if cfg.NumTrees <= 0 {
		cfg.NumTrees = 50
	}
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 8
	}
	return &IForestModel{
		name:     cfg.Name,
		version:  cfg.Version,
		features: cfg.Features,
		numTrees: cfg.NumTrees,
		maxDepth: cfg.MaxDepth,
	}
}

// Name 满足 Model interface。
func (m *IForestModel) Name() string { return m.name }

// Version 满足 Model interface。
func (m *IForestModel) Version() string { return m.version }

// FeatureNames 满足 Model interface。
func (m *IForestModel) FeatureNames() []string { return m.features }

// Predict 计算单条样本异常分数 [0, 1]。
//
// 未训练时返回 0.5 不带 label。
func (m *IForestModel) Predict(features []float64) (float64, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.trees) == 0 {
		return 0.5, "", nil
	}
	var total float64
	for _, t := range m.trees {
		total += float64(t.pathLength(features, 0))
	}
	avg := total / float64(len(m.trees))
	// 标准 IForest score: s(x, n) = 2^(-E(h(x)) / c(n))
	// 这里 c(n) 用样本数近似;简化为 2^(-avg / maxDepth)
	score := math.Pow(2, -avg/float64(m.maxDepth))
	label := "normal"
	if score > 0.6 {
		label = "anomaly"
	}
	return score, label, nil
}

// Train 用一批样本训练模型。
//
// 样本数应 ≥ 100; 少于此时模型不可靠。
func (m *IForestModel) Train(samples [][]float64) {
	if len(samples) == 0 {
		return
	}
	rng := rand.New(rand.NewSource(int64(len(samples))))
	trees := make([]*iTree, 0, m.numTrees)
	for i := 0; i < m.numTrees; i++ {
		// 随机子采样 (每棵树用 256 样本或全部)
		size := 256
		if size > len(samples) {
			size = len(samples)
		}
		sub := make([][]float64, size)
		for j := 0; j < size; j++ {
			sub[j] = samples[rng.Intn(len(samples))]
		}
		trees = append(trees, buildTree(sub, m.maxDepth, rng))
	}
	m.mu.Lock()
	m.trees = trees
	m.mu.Unlock()
}

// iTree 是单棵 Isolation Tree。
type iTree struct {
	feature  int     // split 特征 index
	value    float64 // split 值
	left     *iTree
	right    *iTree
	leafSize int // leaf 节点的样本数
}

func buildTree(samples [][]float64, maxDepth int, rng *rand.Rand) *iTree {
	if len(samples) == 0 {
		return nil
	}
	return buildNode(samples, 0, maxDepth, rng)
}

func buildNode(samples [][]float64, depth, maxDepth int, rng *rand.Rand) *iTree {
	if depth >= maxDepth || len(samples) <= 1 {
		return &iTree{leafSize: len(samples)}
	}
	if len(samples[0]) == 0 {
		return &iTree{leafSize: len(samples)}
	}
	// 随机选 feature 和 split 值
	feature := rng.Intn(len(samples[0]))
	minVal, maxVal := math.Inf(1), math.Inf(-1)
	for _, s := range samples {
		if s[feature] < minVal {
			minVal = s[feature]
		}
		if s[feature] > maxVal {
			maxVal = s[feature]
		}
	}
	if minVal == maxVal {
		return &iTree{leafSize: len(samples)}
	}
	value := minVal + rng.Float64()*(maxVal-minVal)

	var left, right [][]float64
	for _, s := range samples {
		if s[feature] < value {
			left = append(left, s)
		} else {
			right = append(right, s)
		}
	}
	return &iTree{
		feature: feature,
		value:   value,
		left:    buildNode(left, depth+1, maxDepth, rng),
		right:   buildNode(right, depth+1, maxDepth, rng),
	}
}

// pathLength 计算样本在树中走到 leaf 的路径长度。
func (t *iTree) pathLength(features []float64, depth int) int {
	if t == nil {
		return depth
	}
	if t.left == nil && t.right == nil {
		return depth
	}
	if t.feature >= len(features) {
		return depth
	}
	if features[t.feature] < t.value {
		return t.left.pathLength(features, depth+1)
	}
	return t.right.pathLength(features, depth+1)
}

// 编译期断言
var _ Model = (*IForestModel)(nil)
