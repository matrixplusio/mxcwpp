// Package replay 用标注语料回放检测规则，测量召回率与误报率。
//
// 平台此前无法回答"漏了多少"。已关闭告警数只能反映看过的东西，而漏报的定义
// 恰恰是没人看见——用生产数据算召回，等于用"我没发现问题"证明"没有问题"。
//
// 召回只能对着标注语料算：先写下攻击应当长什么样，再看规则是否命中。
// 语料没覆盖到的技术，召回率是未知，不是 100%。
package replay

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Label 是一条语料的标注。
type Label string

const (
	// LabelAttack 攻击样本，规则应当命中。漏掉即漏报。
	LabelAttack Label = "attack"
	// LabelBenign 正常业务样本，规则不应命中。命中即误报。
	//
	// 正常语料和攻击语料一样重要：只测攻击样本，一条恒真规则能拿满分。
	LabelBenign Label = "benign"
)

// Sample 是一条标注事件。
type Sample struct {
	// Name 样本名，出现在失败输出里，要能直接看懂是什么场景。
	Name string `json:"name"`
	// Label 标注。
	Label Label `json:"label"`
	// Technique ATT&CK 技术 ID，如 T1059.004。按技术聚合召回率用。
	Technique string `json:"technique,omitempty"`
	// DataType 事件类型。
	DataType int32 `json:"data_type"`
	// Fields 事件字段。
	Fields map[string]string `json:"fields"`
	// Note 说明该样本为什么这样标注——尤其是 benign 样本，
	// 因为"这看起来很像攻击但确实是正常的"正是最容易被调错的地方。
	Note string `json:"note,omitempty"`
}

// Corpus 是一组标注样本。
type Corpus struct {
	Samples []Sample `json:"samples"`
}

// Validate 检查语料自身是否可用。
//
// 语料错了比没有语料更糟：一份标注混乱的语料会给出一个看起来很高的分数，
// 然后所有人都会拿它当依据。
func (c *Corpus) Validate() error {
	if len(c.Samples) == 0 {
		return fmt.Errorf("语料为空")
	}
	seen := make(map[string]bool, len(c.Samples))
	var attack, benign int
	for i, s := range c.Samples {
		if strings.TrimSpace(s.Name) == "" {
			return fmt.Errorf("第 %d 条样本缺少名称", i)
		}
		if seen[s.Name] {
			return fmt.Errorf("样本名重复: %s", s.Name)
		}
		seen[s.Name] = true
		switch s.Label {
		case LabelAttack:
			attack++
			if s.Technique == "" {
				return fmt.Errorf("攻击样本 %s 缺少 ATT&CK 技术 ID（无法按技术归集召回率）", s.Name)
			}
		case LabelBenign:
			benign++
		default:
			return fmt.Errorf("样本 %s 的标注非法: %q", s.Name, s.Label)
		}
		if len(s.Fields) == 0 {
			return fmt.Errorf("样本 %s 没有任何字段", s.Name)
		}
	}
	// 只有攻击样本的语料测不出误报，只有正常样本的测不出漏报。
	// 两边都要有，否则这份语料只能证明它想证明的那一半。
	if attack == 0 {
		return fmt.Errorf("语料缺少攻击样本，无法测量召回率")
	}
	if benign == 0 {
		return fmt.Errorf("语料缺少正常样本，无法测量误报——只测攻击样本时一条恒真规则也能满分")
	}
	return nil
}

// Load 从目录读取全部 .json 语料文件并合并。
func Load(dir string) (*Corpus, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("读取语料目录失败: %w", err)
	}
	var all Corpus
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("读取 %s 失败: %w", e.Name(), err)
		}
		var c Corpus
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("解析 %s 失败: %w", e.Name(), err)
		}
		all.Samples = append(all.Samples, c.Samples...)
	}
	sort.Slice(all.Samples, func(i, j int) bool { return all.Samples[i].Name < all.Samples[j].Name })
	return &all, nil
}
