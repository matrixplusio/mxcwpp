package deploy

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// chExemptPath 是「已建表但暂无写入方」的登记清单。
const chExemptPath = "testdata/clickhouse-tables-without-writer.tsv"

// TestEveryClickHouseTableHasAWriter 建了的 ClickHouse 表必须有人往里写。
//
// 未接线门禁盯的是 Go 包有没有导入者，盯不到这一类：表建在 SQL 脚本里，
// 部署时照常创建，查询它的代码也能编译通过——只是永远查到空。于是会出现
// 对着零行表做统计的接口，而日志、指标、测试全都正常。
//
// 判据取「有没有 INSERT INTO <表名>」。它不能证明写入真的在跑（那只有端到端
// 有数据才算数），但能挡住「压根没人写」这一类，成本近乎为零。
// 物化视图由源表驱动，不需要显式写入，故不在检查范围。
func TestEveryClickHouseTableHasAWriter(t *testing.T) {
	root := repoRootFromDeploy(t)

	tables := clickHouseTables(t, filepath.Join(root, "deploy", "init-clickhouse.sql"))
	if len(tables) == 0 {
		t.Fatal("从 deploy/init-clickhouse.sql 里没解析出任何表——" +
			"要么脚本挪走了，要么这条检查已经失效")
	}

	writers := clickHouseWriters(t, root)
	declared := readCHExemptions(t, root)

	var missing, stale []string
	for _, tbl := range tables {
		_, hasWriter := writers[tbl]
		_, exempt := declared[tbl]
		switch {
		case !hasWriter && !exempt:
			missing = append(missing, tbl)
		case hasWriter && exempt:
			stale = append(stale, tbl)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)

	if len(missing) > 0 {
		t.Errorf("以下 ClickHouse 表没有任何 INSERT INTO，也不在 %s 中：\n  %s\n\n"+
			"要么接线，要么从建表脚本里删掉，要么在清单里写明为什么它还留着。",
			chExemptPath, strings.Join(missing, "\n  "))
	}
	if len(stale) > 0 {
		t.Errorf("以下表已经有写入方，请从 %s 移除：\n  %s",
			chExemptPath, strings.Join(stale, "\n  "))
	}
}

// clickHouseTables 解析建表脚本里的表名（不含物化视图）。
func clickHouseTables(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", path, err)
	}
	re := regexp.MustCompile(`(?im)^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?` +
		"`?(?:mxcwpp\\.)?([a-z_][a-z0-9_]*)`?")
	var out []string
	for _, m := range re.FindAllStringSubmatch(string(data), -1) {
		out = append(out, m[1])
	}
	return out
}

// clickHouseWriters 扫描 Go 源码里出现过的 INSERT INTO 目标表。
func clickHouseWriters(t *testing.T, root string) map[string]struct{} {
	t.Helper()
	re := regexp.MustCompile(`(?i)INSERT\s+INTO\s+` + "`?(?:mxcwpp\\.)?([a-z_][a-z0-9_]*)")
	out := map[string]struct{}{}
	forEachTrackedFile(t, root, func(rel string, data []byte) {
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return
		}
		for _, m := range re.FindAllSubmatch(data, -1) {
			out[string(m[1])] = struct{}{}
		}
	})
	return out
}

// readCHExemptions 读取豁免清单，返回 表名 -> 原因。
func readCHExemptions(t *testing.T, root string) map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join(root, "internal", "deploy", chExemptPath))
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}
		}
		t.Fatalf("读取豁免清单失败: %v", err)
	}
	defer f.Close()

	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		name, reason, ok := strings.Cut(text, "\t")
		if !ok || strings.TrimSpace(reason) == "" {
			t.Errorf("%s:%d 缺少原因；一张没人写的表留在部署脚本里，"+
				"必须说清为什么", chExemptPath, line)
			continue
		}
		out[strings.TrimSpace(name)] = strings.TrimSpace(reason)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
