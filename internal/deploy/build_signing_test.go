package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProductionBuildRequiresSigningKey 生产构建必须要求插件签名公钥。
//
// agent 的 verifySignature 在公钥为空时会跳过整道校验，只留一条 Warn 日志。
// 这条 fail-open 分支之所以可以接受，唯一的理由是构建脚本不允许生产构建
// 在缺少 SIGN_PUBLIC_KEY 的情况下产出二进制。若那道闸门被删掉，
// 结果是一批"校验看起来在跑、实际从未生效"的 agent——日志里没有报错，
// 只有一行 Warn，没有任何指标或告警会指出插件是未经校验执行的。
func TestProductionBuildRequiresSigningKey(t *testing.T) {
	root := repoRootFromDeploy(t)
	path := filepath.Join(root, "scripts", "build.sh")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", path, err)
	}
	script := string(data)

	if !strings.Contains(script, "SIGN_PUBLIC_KEY") {
		t.Fatal("scripts/build.sh 不再提及 SIGN_PUBLIC_KEY——" +
			"agent 将带着空公钥出厂，插件签名校验被整体跳过")
	}

	// 闸门的形态可以变，但"缺少签名公钥的生产构建必须失败"这件事不能没有。
	if !strings.Contains(script, `-z "${SIGN_PUBLIC_KEY:-}"`) {
		t.Error("scripts/build.sh 里找不到 SIGN_PUBLIC_KEY 为空的判断；" +
			"若改写了判断方式，请同步更新本测试并确认仍然 exit 非零")
	}
	if !strings.Contains(script, "插件签名校验必需") {
		t.Error("SIGN_PUBLIC_KEY 缺失时的失败提示不见了；" +
			"没有这句提示，构建者只会看到一次退出，不知道该补什么")
	}
}
