package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBuildIsReproducible 构建脚本必须产出可复现的二进制。
//
// 两处会破坏可复现：
//   - 缺 -trimpath：二进制里嵌入构建机的绝对路径（本仓库实测 3985 处），
//     换台机器构建结果就不同，且泄露构建环境；
//   - 嵌入 date 时间戳：同一份源码每次构建产出不同二进制，客户拿到的包
//     无法与源码对账，出问题时也无法确认"跑的到底是不是这份代码"。
func TestBuildIsReproducible(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}

	build, err := os.ReadFile(filepath.Join(root, "scripts", "build.sh"))
	if err != nil {
		t.Fatalf("读取构建脚本失败: %v", err)
	}
	script := string(build)

	if strings.Count(script, "-trimpath") == 0 {
		t.Error("构建脚本缺少 -trimpath，二进制会嵌入构建机绝对路径且跨机不可复现")
	}
	if strings.Contains(script, `BUILD_TIME=$(date -u +`) &&
		!strings.Contains(script, "SOURCE_DATE_EPOCH") {
		t.Error("构建时间取当前时间且无 SOURCE_DATE_EPOCH 兜底，同一源码每次构建结果不同")
	}
	for _, must := range []string{
		"SOURCE_DATE_EPOCH", // 可复现构建通行约定
		"git log -1 --format=%cI",
		"main.gitCommit=$GIT_COMMIT", // 交付后与源码对账
	} {
		if !strings.Contains(script, must) {
			t.Errorf("构建脚本缺少 %q", must)
		}
	}

	// Makefile 是另一条构建路径，两条产出必须一致，否则"可复现"只对其中一条成立。
	mk, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("读取 Makefile 失败: %v", err)
	}
	if strings.Contains(string(mk), `go build -ldflags "-s -w"`) {
		t.Error("Makefile 仍有未加 -trimpath 的构建，与 build.sh 产出不一致")
	}
}

// TestSBOMShipsWithPackage 发布包必须带物料清单。
//
// 没有 SBOM 的交付物在合规审计里过不去，也无法在供应链事件发生时快速自查。
func TestSBOMShipsWithPackage(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(root, "scripts", "gen-sbom.sh")); err != nil {
		t.Fatalf("缺少 SBOM 生成脚本: %v", err)
	}
	pkg, err := os.ReadFile(filepath.Join(root, "scripts", "package-deploy.sh"))
	if err != nil {
		t.Fatalf("读取打包脚本失败: %v", err)
	}
	if !strings.Contains(string(pkg), "gen-sbom.sh") {
		t.Error("打包脚本未生成 SBOM，发布包缺少物料清单")
	}
}
