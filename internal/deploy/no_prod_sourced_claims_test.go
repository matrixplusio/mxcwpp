package deploy

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// 生产来源声明门禁。
//
// 与地址门禁互补：那道闸拦的是"长得像真实地址的字符串"，这道闸拦的是**来源**。
// 一个数字读起来再像技术依据，只要它是从生产环境看来的，写进公开仓库就等于
// 发布运行数据——规模、事故经过、误报率、主机台数，拼起来足以刻画一套真实系统。
//
// 判据是来源不是长相，所以无法靠白名单表达；这里拦的是"来源标记 + 具体数字"
// 这个组合。单独的性能基准（实验室压测、微基准）不带来源标记，不会被拦。
//
// 需要记录真实环境细节时写到 local-reports/（已 gitignore），不要写进仓库。

// prodSourceMarkers 是把一句话标记为"取自生产环境"的措辞。
//
// 这些词本身不是机密（是通用中文/英文），可以留在仓库里；真正需要保密的
// 组织标识走 .production-identifiers（gitignore），由 TestNoLocalDeniedTerms 覆盖。
var prodSourceMarkers = []string{
	"prod 实测", "prod实测", "prod 上", "生产实测", "生产环境实测",
	"线上实测", "现网实测", "生产上表现", "生产表现",
	"on the live fleet", "the live fleet", "in production",
}

// quantityRe 匹配"具体数字"：四位以上整数、带千分位的数、或带量词的数。
//
// 三位以内的裸数字不算——端口号、超时秒数、重试次数都是配置常量，
// 拦它们只会制造噪声。
var quantityRe = regexp.MustCompile(
	`\d{4,}|\d{1,3}(,\d{3})+|\d+(\.\d+)?\s*[kKwW]\+?|\d+(\.\d+)?\s*(万|亿|台|条|次|个|行|GB|TB|%|/天|/秒|/周)`)

// TestNoProdSourcedClaims 仓库里不得出现"生产来源 + 具体数字"的组合。
func TestNoProdSourcedClaims(t *testing.T) {
	var findings []string

	root := repoRootFromDeploy(t)
	forEachTrackedFile(t, root, func(rel string, data []byte) {
		if rel == "internal/deploy/no_prod_sourced_claims_test.go" {
			return // 本文件自带示例
		}
		for i, line := range strings.Split(string(data), "\n") {
			marker := firstMarker(line)
			if marker == "" || !quantityRe.MatchString(line) {
				continue
			}
			findings = append(findings, fmt.Sprintf("%s:%d\n      标记 %q + 具体数字：%s",
				rel, i+1, marker, strings.TrimSpace(trunc(line, 110))))
		}
	})

	if len(findings) > 0 {
		t.Errorf("受跟踪文件中出现「生产来源 + 具体数字」的表述，共 %d 处。\n"+
			"本仓库对外发布，这类内容会把生产环境的规模与事故经过一并发布出去，\n"+
			"而且进入提交后在 git 历史中永久可查。\n\n%s\n\n"+
			"改法：把数字换成量级（\"数十万条\"）或删掉来源标记只留技术判据；\n"+
			"确需记录真实环境细节，写到 local-reports/（已 gitignore）。",
			len(findings), strings.Join(findings, "\n    "))
	}
}

// TestProdSourceMarkersAreDetected 门禁必须真的能抓到典型写法。
//
// 没有这条，上面那个测试在正则写错时会永远通过——一个从不失败的门禁
// 比没有门禁更糟，因为它让人以为这件事有人管。
func TestProdSourceMarkersAreDetected(t *testing.T) {
	shouldCatch := []string{
		"// prod 实测 1234 台主机某计数器全为 0",
		"// 生产实测：30 分钟 111,111 条事件",
		"// 线上实测这三条规则单周命中 99 万次",
		"// on the live fleet this produced 1,111 open alerts",
		"// prod 上一次升级累积了 2,222 条告警",
		"-- prod 实测达 11k+ 条",
		"// 逐条打日志会撑爆磁盘（prod 实测 ~999GB/天）",
	}
	for _, s := range shouldCatch {
		if firstMarker(s) == "" {
			t.Errorf("未识别出生产来源标记：%s", s)
			continue
		}
		if !quantityRe.MatchString(s) {
			t.Errorf("未识别出具体数字：%s", s)
		}
	}
}

// TestLabBenchmarksAreNotFlagged 实验室基准不带来源标记，不能被误拦。
//
// 误拦的代价是这道闸会被当成噪声关掉，那就退回到没有门禁的状态。
func TestLabBenchmarksAreNotFlagged(t *testing.T) {
	shouldPass := []string{
		"// 实测 (CentOS 7 / 4.18 内核, 100Mbps 流量): 单包处理 1.2us",
		"// 实测兼容矩阵: 4.18 / 5.4 / 5.15",
		"// 单次 transform 平均 < 5ms (实测 Runtime: 1.8ms)",
		"// 本仓库实测 3985 处绝对路径",
		`t.Errorf("NEVRA epoch 0<2 应判 needs update，实测 %+v", out[0])`,
		"const scanPortThreshold = 10",
		"// TTL 只有 300 秒，排空 50000 条需要 370 秒",
	}
	for _, s := range shouldPass {
		if m := firstMarker(s); m != "" {
			t.Errorf("误拦实验室基准（命中 %q）：%s", m, s)
		}
	}
}

// TestNoOrgIdentifiers 组织标识不得出现在仓库里。
//
// 与"来源 + 数字"那条互补：业务线编号不需要搭配数字
// 就已经能把内容关联到具体组织。这类词的**样式**是通用的（形如 line-b 的
// 业务线编号），写在这里不泄露什么；真实主机名前缀等需要保密的
// 具体名字走 .production-identifiers（gitignore）。
func TestNoOrgIdentifiers(t *testing.T) {
	// 只匹配通用形态：形如 line-b 的业务线编号。
	// 真实主机名前缀不写在这里——它们本身就是敏感项，登记在 .production-identifiers，
	// 由 TestNoLocalDeniedTerms 覆盖。两道闸互补，都不需要把机密写进仓库。
	orgRe := regexp.MustCompile(`G0\d-(UAT|PROD)`)

	var findings []string
	root := repoRootFromDeploy(t)
	forEachTrackedFile(t, root, func(rel string, data []byte) {
		if rel == "internal/deploy/no_prod_sourced_claims_test.go" {
			return
		}
		for i, line := range strings.Split(string(data), "\n") {
			if m := orgRe.FindString(line); m != "" {
				findings = append(findings, fmt.Sprintf("%s:%d  命中 %q：%s",
					rel, i+1, m, strings.TrimSpace(trunc(line, 96))))
			}
		}
	})
	if len(findings) > 0 {
		t.Errorf("受跟踪文件中出现组织标识，共 %d 处。\n"+
			"业务线编号能直接把仓库内容关联到具体组织。\n\n%s\n\n"+
			"改法：测试固件用中性名（line-a / host-1），注释里描述角色而非具体实例。",
			len(findings), strings.Join(findings, "\n    "))
	}
}

// TestOrgIdentifierPatternWorks 门禁必须真的能抓到，也不能误伤中性名。
func TestOrgIdentifierPatternWorks(t *testing.T) {
	orgRe := regexp.MustCompile(`G0\d-(UAT|PROD)`)
	for _, s := range []string{
		`BusinessLine: "G09-UAT"`,
		`BusinessLine: "G09-PROD"`,
		"// G09-UAT 上复现",
	} {
		if !orgRe.MatchString(s) {
			t.Errorf("未抓到组织标识：%s", s)
		}
	}
	for _, s := range []string{
		`BusinessLine: "line-a"`,
		`hostname := "host-1"`,
		"// G1 阶段的 GC 行为",
		"const gcpProject = \"example-project\"",
	} {
		if m := orgRe.FindString(s); m != "" {
			t.Errorf("误伤中性名（命中 %q）：%s", m, s)
		}
	}
}

func firstMarker(line string) string {
	lower := strings.ToLower(line)
	for _, m := range prodSourceMarkers {
		if strings.Contains(lower, strings.ToLower(m)) {
			return m
		}
	}
	return ""
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
