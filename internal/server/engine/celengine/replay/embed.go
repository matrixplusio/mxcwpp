package replay

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
)

// builtinCorpus 随二进制发布的标注语料，engine 用它检查白名单会不会压掉已知攻击。
//
//go:embed testdata/corpus/*.json
var builtinCorpus embed.FS

// Builtin 读取随二进制发布的标注语料。
func Builtin() (*Corpus, error) {
	files, err := fs.Glob(builtinCorpus, "testdata/corpus/*.json")
	if err != nil {
		return nil, fmt.Errorf("列出内置语料失败: %w", err)
	}
	var all Corpus
	for _, f := range files {
		data, err := builtinCorpus.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("读取 %s 失败: %w", f, err)
		}
		var c Corpus
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("解析 %s 失败: %w", f, err)
		}
		all.Samples = append(all.Samples, c.Samples...)
	}
	sort.Slice(all.Samples, func(i, j int) bool { return all.Samples[i].Name < all.Samples[j].Name })
	return &all, nil
}

// Attacks 返回语料里的攻击样本。
func (c *Corpus) Attacks() []Sample {
	var out []Sample
	for _, s := range c.Samples {
		if s.Label == LabelAttack {
			out = append(out, s)
		}
	}
	return out
}
