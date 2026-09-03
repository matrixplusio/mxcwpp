package anomaly

import (
	"encoding/json"
	"fmt"
)

// 森林序列化。
//
// 此前模型只活在内存里：进程一重启就要重新攒样本、再等一个重训周期（30 分钟）
// 才恢复评分能力。这段时间检测器照常运行、指标照常上报，只是什么都发现不了——
// 发布、扩容、崩溃恢复都会触发。
//
// 序列化同时是版本与回滚的前提：能存下来才能存多份，能存多份才谈得上回退。

// forestSnapshot 是 IForest 的可序列化镜像。
//
// 单独定义而不给原结构加 tag：原结构的字段刻意不导出，导出它们会让森林
// 在包外可被随意改写，而模型被外部改一下就再也说不清它学到了什么。
type forestSnapshot struct {
	// Psi 训练时的子采样规模。
	Psi int `json:"psi"`
	// C psi 对应的平均路径长度常数。存下来而不是重算，
	// 避免将来常数公式微调后，旧模型的分数含义悄悄变了。
	C float64 `json:"c"`
	// Trees 每棵树的根节点。
	Trees []*nodeSnapshot `json:"trees"`
	// Features 训练时的特征维数，用于加载时校验。
	Features int `json:"features"`
}

// nodeSnapshot 是 iNode 的可序列化镜像。
type nodeSnapshot struct {
	Left      *nodeSnapshot `json:"l,omitempty"`
	Right     *nodeSnapshot `json:"r,omitempty"`
	SplitAttr int           `json:"a,omitempty"`
	SplitVal  float64       `json:"v,omitempty"`
	Size      int           `json:"s,omitempty"`
	Height    int           `json:"h,omitempty"`
}

// Snapshot 导出当前森林。未训练时返回 nil。
func (f *IForest) Snapshot() *forestSnapshot {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(f.trees) == 0 {
		return nil
	}
	snap := &forestSnapshot{
		Psi:      f.psi,
		C:        f.c,
		Features: featureCount,
		Trees:    make([]*nodeSnapshot, 0, len(f.trees)),
	}
	for _, t := range f.trees {
		if t == nil {
			continue
		}
		snap.Trees = append(snap.Trees, encodeNode(t.root))
	}
	return snap
}

func encodeNode(n *iNode) *nodeSnapshot {
	if n == nil {
		return nil
	}
	return &nodeSnapshot{
		Left:      encodeNode(n.left),
		Right:     encodeNode(n.right),
		SplitAttr: n.splitAttr,
		SplitVal:  n.splitVal,
		Size:      n.size,
		Height:    n.height,
	}
}

// LoadSnapshot 用快照替换当前森林。
//
// 校验失败一律拒绝并保留原模型：宁可继续用旧模型，也不要装载一个结构可疑的新模型。
// 半个森林比没有森林更危险——它照样给分，只是分数不再有意义。
func (f *IForest) LoadSnapshot(snap *forestSnapshot) error {
	if snap == nil {
		return fmt.Errorf("快照为空")
	}
	if snap.Features != featureCount {
		return fmt.Errorf("快照特征维数 %d 与当前 %d 不符（特征变更后旧模型的每一维含义都已错位）",
			snap.Features, featureCount)
	}
	if len(snap.Trees) == 0 {
		return fmt.Errorf("快照不含任何树")
	}
	if snap.Psi <= 0 || snap.C <= 0 {
		return fmt.Errorf("快照的 psi=%d / c=%f 非法", snap.Psi, snap.C)
	}
	trees := make([]*iTree, 0, len(snap.Trees))
	for i, ns := range snap.Trees {
		root := decodeNode(ns)
		if root == nil {
			return fmt.Errorf("第 %d 棵树为空", i)
		}
		trees = append(trees, &iTree{root: root})
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.trees = trees
	f.psi = snap.Psi
	f.c = snap.C
	return nil
}

func decodeNode(n *nodeSnapshot) *iNode {
	if n == nil {
		return nil
	}
	return &iNode{
		left:      decodeNode(n.Left),
		right:     decodeNode(n.Right),
		splitAttr: n.SplitAttr,
		splitVal:  n.SplitVal,
		size:      n.Size,
		height:    n.Height,
	}
}

// MarshalForest 把森林序列化为 JSON。未训练返回 nil, nil。
func (f *IForest) MarshalForest() ([]byte, error) {
	snap := f.Snapshot()
	if snap == nil {
		return nil, nil
	}
	return json.Marshal(snap)
}

// UnmarshalForest 从 JSON 恢复森林。
func (f *IForest) UnmarshalForest(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("模型数据为空")
	}
	var snap forestSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("解析模型失败: %w", err)
	}
	return f.LoadSnapshot(&snap)
}
