package deploy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"

	commoncfg "github.com/matrixplusio/mxcwpp/internal/server/common/config"
	servercfg "github.com/matrixplusio/mxcwpp/internal/server/config"
)

// TestConfigSamplesMatchCode configs/ 下的配置样例必须与代码里的配置结构一致。
//
// LLMProxy 目前不读取 configs/llmproxy.yaml，不在此列。
//
// 各服务的加载函数都很宽松：文件找不到就用默认值，认不出的键直接忽略。所以样例写错了、
// 或者代码改了字段名，服务照样启动，只是配置没有生效。这里按严格模式解码，样例里出现
// 结构体不认识的键就失败。
func TestConfigSamplesMatchCode(t *testing.T) {
	root := repoRootFromDeploy(t)
	for _, c := range []struct {
		file   string
		target any
	}{
		{"configs/server.yaml.example", &servercfg.Config{}},
		{"configs/vulnsync.yaml", &servercfg.Config{}},
		{"configs/engine.yaml", &commoncfg.EngineConfig{}},
	} {
		path := filepath.Join(root, c.file)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s 不存在：%v", c.file, err)
			continue
		}
		v := viper.New()
		v.SetConfigFile(path)
		v.SetConfigType("yaml")
		if err := v.ReadInConfig(); err != nil {
			t.Errorf("%s 读取失败：%v", c.file, err)
			continue
		}
		if err := v.UnmarshalExact(c.target); err != nil {
			t.Errorf("%s 与代码里的配置结构不一致：%v", c.file, err)
		}
	}
	if _, err := commoncfg.LoadEngine(filepath.Join(root, "configs/engine.yaml")); err != nil {
		t.Errorf("Engine 加载 configs/engine.yaml 失败：%v", err)
	}
	// 服务端按扩展名判断格式，样例要按使用方式复制成 .yaml 再加载
	data, err := os.ReadFile(filepath.Join(root, "configs/server.yaml.example"))
	if err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(copied, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := servercfg.Load(copied); err != nil {
		t.Errorf("服务端加载 configs/server.yaml.example 失败：%v", err)
	}
}
