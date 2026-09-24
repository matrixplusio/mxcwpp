package deploy

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// 生产来源声明门禁。
//
// 与地址门禁互补：那道闸拦的是"长得像真实地址的字符串"，这道闸拦的是**来源**。
// 一个数字读起来再像技术依据，只要它是从生产环境看来的，写进公开仓库就等于
// 发布运行数据——规模、事故经过、误报率、主机台数，拼起来足以刻画一套真实系统。
//
// 规则只有一份：.githooks/leakscan.sh（来源标记在 .githooks/prod-claim-patterns）。
// pre-commit、pre-push 与这里都调用它。此前 Go 与 shell 各写一份词表，
// 两边都漏了「生产上曾有」「实测 prod」「prod 后面跟日期再接实测」这类写法，
// 公开仓库里因此留下了十几处生产数字。
//
// 需要记录真实环境细节时写到 local-reports/（已 gitignore），不要写进仓库。

// leakscan 把「位置<TAB>文本」行交给 .githooks/leakscan.sh，返回它的报告。
func leakscan(t *testing.T, root, input string) (report string, clean bool) {
	t.Helper()
	cmd := exec.Command("bash", "-c", `. .githooks/leakscan.sh && leakscan_lines`)
	cmd.Dir = root
	cmd.Stdin = strings.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return "", true
	}
	if _, ok := err.(*exec.ExitError); !ok {
		t.Fatalf("无法运行 leakscan.sh：%v", err)
	}
	return stderr.String(), false
}

// TestNoProdSourcedClaims 受跟踪文件不得含生产来源表述、业务线编号与凭证。
//
// 与 pre-push 扫的是同一套规则；区别只在范围：pre-push 扫要推的每个 commit 的
// 新增行，这里扫当前树的全部文本文件。
func TestNoProdSourcedClaims(t *testing.T) {
	root := repoRootFromDeploy(t)
	out, err := exec.Command("git", "-C", root, "ls-files").Output()
	if err != nil {
		t.Skipf("git ls-files 失败（可能不在工作树内），跳过: %v", err)
	}

	var in strings.Builder
	for _, rel := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		// 本文件持有「必须被拦下」的反例字符串，它们按定义会命中。
		if rel == "" || shouldSkipPath(rel) || rel == "internal/deploy/no_prod_sourced_claims_test.go" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil || bytes.IndexByte(data[:min(len(data), 8000)], 0) >= 0 {
			continue // 已删除，或二进制
		}
		for i, line := range strings.Split(string(data), "\n") {
			// 只送可能命中的行：来源、实测、业务线规则都要求有数字，凭证里只有私钥头不带数字。
			// macOS 自带的 BSD grep 扫全树要二十多秒，预筛后降到几秒。
			// 本地字典与地址另有 TestNoLocalDeniedTerms / TestNoUndocumentedAddresses 全量覆盖。
			if !strings.ContainsAny(line, "0123456789") && !strings.Contains(line, "PRIVATE KEY") {
				continue
			}
			in.WriteString(rel + ":" + strconv.Itoa(i+1) + "\t" + line + "\n")
		}
	}

	if report, clean := leakscan(t, root, in.String()); !clean {
		t.Errorf("受跟踪文件中出现不该公开的内容。本仓库对外发布，\n"+
			"进入提交后在 git 历史中永久可查，fork 与克隆收不回。\n\n%s\n"+
			"改法：数字换成量级（\"数十万条\"），或删掉来源只留机制；\n"+
			"确需记录真实环境细节，写到 local-reports/（已 gitignore）。", report)
	}
}

// TestLeakscanCatchesKnownShapes 门禁必须真的抓得到。
//
// 下面每一条都是某次真实漏出去的写法换成假数字后的样子。没有这条，
// 规则写错时上面那个测试会永远通过——一个从不失败的门禁比没有更糟，
// 因为它让人以为这件事有人管。
//
// 这些行在源码里带 leakscan:example 标记，所以提交与推送时不会拦本文件；
// 送进扫描器的只是引号里的字符串，不带标记。
func TestLeakscanCatchesKnownShapes(t *testing.T) {
	root := repoRootFromDeploy(t)
	for _, s := range []string{
		"// prod 实测 1234 台主机某计数器全为 0",                          // leakscan:example
		"// 生产实测：30 分钟 111,111 条事件",                            // leakscan:example
		"// 线上实测这三条规则单周命中 99 万次",                               // leakscan:example
		"// on the live fleet this produced 1,111 open alerts", // leakscan:example
		"// prod 上一次升级累积了 2,222 条告警",                           // leakscan:example
		"-- prod 实测达 11k+ 条",                                   // leakscan:example
		"// 逐条打日志会撑爆磁盘（prod 实测 ~999GB/天）",                      // leakscan:example
		"// 实测 prod 1.23M 行表 45.6s → 改走索引后毫秒级",                 // leakscan:example
		"// 业务背景:prod 2099-01-01 实测 12% (123/4567) 无 CVSS",     // leakscan:example
		"// 判定必须用它——生产上曾有 11,111 条关联被误判为已修复",                   // leakscan:example
		"// patched 数因此被严重低估（生产上 111 vs 22222）",                // leakscan:example
		`"note": "prod 实例：临时源端口恰为 3333，挂了两个月（alerts#9999）"`,    // leakscan:example
		"// （实测 advisory 全量严重 1111 vs 舰队真实 22）",                // leakscan:example
		"// 非恶意父进程派生。(2099-07 prod 巡检:CDN 单条 12w hit)",         // leakscan:example
		"// 回归 2099-08 事故：单条故事线攒到千万级明细",                        // leakscan:example
		"## CVE 级 vs 实例级举例(prod 2099-07-02)",                   // leakscan:example
		"--   1.23 亿行规模下 LIMIT 50 > 10s（实测）",                   // leakscan:example
		"// 同一稳态偏离每快照一行，实测积压 ~123 万全 open",                     // leakscan:example
		"// 造成大量自检测误报(实测单条 hit 1111)",                          // leakscan:example
		`{HostID: "h-3", BusinessLine: "G09-PROD"}`,            // leakscan:example
		"// G09-UAT 上复现", // leakscan:example
		"sudo ssh -p 2222 u@h 'clickhouse-client --password 0a1b2c3d4e5f6a7b8c9d'", // leakscan:example
		"-----BEGIN RSA PRIVATE KEY-----",                                          // leakscan:example
		"clickhouse://reader:Zx81kLq0pp@db.example:9000/app",                       // leakscan:example
		`"private_key_id": "0123456789abcdef0123456789abcdef01234567"`,             // leakscan:example
	} {
		if _, clean := leakscan(t, root, "fixture\t"+s+"\n"); clean {
			t.Errorf("门禁没拦住：%s", s)
		}
	}
}

// TestLeakscanPassesNeutralText 中性写法不能被误拦。
//
// 误拦的代价是这道闸会被当成噪声绕过，那就退回到没有门禁的状态。
func TestLeakscanPassesNeutralText(t *testing.T) {
	root := repoRootFromDeploy(t)
	for _, s := range []string{
		"// 实测 (CentOS 7 / 4.18 内核, 100Mbps 流量): 单包处理 1.2us",
		"// 实测兼容矩阵: 4.18 / 5.4 / 5.15",
		"// 单次 transform 平均 < 5ms (实测 Runtime: 1.8ms)",
		"// 本仓库实测 3985 处绝对路径",
		`t.Errorf("NEVRA epoch 0<2 应判 needs update，实测 %+v", out[0])`,
		"const scanPortThreshold = 10",
		"// TTL 只有 300 秒，排空 50000 条需要 370 秒",
		"// 按舰队落地的去重 CVE（host_vulnerabilities join）",
		"//   - Kafka 路径（DataType 6001）写入时，全舰队每个序号只有一行",
		"// 生产者每秒可发 5000 条",
		"image: registry.example/prod-app:1234",
		"// 数十万条事件、千万级行表、近两个数量级",
		`BusinessLine: "line-a"`,
		"password: \"${MYSQL_PASSWORD}\"",
		"clickhouse://user:password@host:9000/app",
		"--password=<pwd>",
		"MYSQL_ADDR=10.0.0.5:3306 PUBLIC=203.0.113.10",
		// 扫描器自己的检测规则：只有键名、没有值，不是凭证
		"Regex: regexp.MustCompile(`\"private_key_id\":\\s*\"[a-f0-9]{40}\"`),",
	} {
		if report, clean := leakscan(t, root, "fixture\t"+s+"\n"); !clean {
			t.Errorf("误拦中性写法：%s\n%s", s, report)
		}
	}
}
