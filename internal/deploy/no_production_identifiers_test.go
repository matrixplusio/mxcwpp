package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// 生产标识门禁。
//
// 本仓库对外发布。真实地址一旦写进提交，`git log -p` 就永久可查，
// 而已被克隆 / fork / 缓存 / 爬取的副本收不回——发现得再早也追不回来。
//
// 靠"提交前记得检查"防不住：真实地址进入仓库从来不是有人刻意写的，
// 而是排查生产问题时顺手把现场证据贴进了测试固件和注释。那一刻它们看着
// 正是最有说服力的用例。只有让构建失败才拦得住。
//
// **判据是白名单，不是黑名单。**
//
// 这一点是这份门禁最关键的设计。黑名单要写下"禁止出现 10.170 段、禁止出现
// 某某公司名"，而门禁本身就在这个公开仓库里——等于把内网网段和公司标识
// 主动登记了一遍，防泄露的东西自己成了泄露源。
//
// 白名单反过来：只列出**允许**出现的文档保留地址，其余一律拦下。它不透露
// 任何真实环境信息，而且更严——今后启用的新网段不必登记就已经被挡住。
//
// 环境特有的字面量（公司名、业务线、主机名前缀）不写进本文件，
// 放在仓库外的 .production-identifiers（见下）。

// documentedPrefixes 是允许出现在仓库中的地址前缀。
//
// 取自 RFC5737（文档用例）、RFC1918 中约定俗成的示例段，以及协议固定地址。
// 新增条目前先问：这个地址是不是任何人看了都不会联想到具体环境？
var documentedPrefixes = []string{
	// RFC5737 文档专用
	"192.0.2.", "198.51.100.", "203.0.113.",
	// RFC1918 惯用示例段。10.0.x 与 192.168.0/1.x 是本仓库的占位约定；
	// 注意 192.168 只放行 .0/.1 两段——真实实验网段用的是别的段，
	// 整段放行会让门禁看不见它们。
	"10.0.", "10.1.2.3", "172.16.", "172.31.255.", "192.168.0.", "192.168.1.",
	// CIDR 边界与非法值：SSRF / 网段判定测试需要跨过边界取样
	"10.255.255.255", "172.32.0.1", "999.",
	// 等保 2.0 条款编号（8.1.4.1 身份鉴别 等），形似地址但不是地址
	"8.1.4.",
	// 容器与编排的约定地址
	"10.96.",   // Kubernetes 默认 Service CIDR
	"172.17.",  // Docker 默认网桥
	"169.254.", // 链路本地，含云元数据 169.254.169.254
	// 回环、任意地址、广播
	"127.", "0.0.0.0", "255.255.255.255",
	// 公共 DNS 与文档域名地址：出现在网络规则与测试里，无环境指向
	"8.8.8.8", "8.8.4.4", "1.1.1.1", "114.114.114.114", "223.5.5.5", "223.6.6.6",
	"93.184.216.34", // example.com
}

// ipv4Re 匹配点分四段。故意宽松：宁可多命中再由白名单与启发式排除，
// 也不要因为正则太精巧而漏掉真实地址。
var ipv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// scanExtensions 限定扫描范围。
//
// 二进制、锁文件、地理数据（web 下的 GeoJSON 含海量坐标数字）不在其列：
// 它们不承载拓扑信息，纳进来只会拖慢测试并制造误报。
var scanExtensions = map[string]bool{
	".go": true, ".yaml": true, ".yml": true, ".tmpl": true,
	".md": true, ".ts": true, ".tsx": true, ".sh": true, ".sql": true,
	// 样例/模板类配置同样会被人照抄，且最容易残留真实地址——
	// configs/server.yaml.example 里就躺过一个，只因后缀不在名单里而漏检。
	".example": true, ".sample": true, ".template": true, ".conf": true, ".cnf": true,
}

// skipPaths 是已由 .gitignore 覆盖、本就用于存放真实环境细节，
// 或因自身职责必须包含反例的路径。
var skipPaths = []string{
	"local-reports/",
	"docs/superpowers/",
	// 本文件持有"必须被拦下"的合成地址作为反例固件（见
	// TestDocumentedPrefixesRejectRealisticAddresses）。它们不属于任何真实环境，
	// 但按定义就在白名单之外，不排除的话这份门禁会永远报自己。
	"internal/deploy/no_production_identifiers_test.go",
}

// localDenyFile 是仓库外的补充清单，每行一个字面量（公司名、业务线、主机名前缀等）。
//
// 存在即生效，不存在则只跑白名单检查。它被 .gitignore 覆盖，
// 因此这些环境特有的词不会随仓库发布——这正是不把它们写进本文件的原因。
const localDenyFile = ".production-identifiers"

// TestNoUndocumentedAddresses 受跟踪文件中不得出现文档白名单之外的 IP 地址。
func TestNoUndocumentedAddresses(t *testing.T) {
	root := repoRootFromDeploy(t)

	var findings []string
	forEachTrackedFile(t, root, func(rel string, data []byte) {
		for _, loc := range ipv4Re.FindAllIndex(data, -1) {
			addr := string(data[loc[0]:loc[1]])
			if isDocumented(addr) || looksLikeVersion(data, loc[0], addr) {
				continue
			}
			findings = append(findings,
				"  "+rel+"\n    出现未登记地址："+addr)
		}
	})

	if len(findings) == 0 {
		return
	}
	t.Error("受跟踪文件中出现文档白名单之外的 IP 地址。本仓库对外发布，\n" +
		"这些地址进入提交后在 git 历史中永久可查，已被克隆的副本无法收回。\n\n" +
		strings.Join(dedupe(findings), "\n") + "\n\n" +
		"改用文档保留地址：203.0.113.x（公网示例）、10.0.0.x（内网示例）。\n" +
		"确需记录真实环境细节，请写到 local-reports/ 或 docs/superpowers/（均已 gitignore）。\n" +
		"若某地址确属通用示例，把前缀加进 documentedPrefixes 并说明理由。")
}

// TestNoLocalDeniedTerms 应用仓库外的补充清单（若存在）。
//
// 公司名、业务线、主机名前缀这类字面量不适合写进公开仓库，
// 故清单本身放在 .production-identifiers（gitignore），有则查、无则跳过。
func TestNoLocalDeniedTerms(t *testing.T) {
	root := repoRootFromDeploy(t)

	raw, err := os.ReadFile(filepath.Join(root, localDenyFile))
	if err != nil {
		t.Skipf("未提供 %s，跳过环境特有字面量检查（白名单地址检查仍然生效）", localDenyFile)
	}
	var terms []string
	for _, ln := range strings.Split(string(raw), "\n") {
		ln = strings.TrimSpace(ln)
		if ln != "" && !strings.HasPrefix(ln, "#") {
			terms = append(terms, ln)
		}
	}
	if len(terms) == 0 {
		t.Skipf("%s 为空，跳过", localDenyFile)
	}

	var findings []string
	forEachTrackedFile(t, root, func(rel string, data []byte) {
		lower := strings.ToLower(string(data))
		for _, term := range terms {
			if strings.Contains(lower, strings.ToLower(term)) {
				findings = append(findings, "  "+rel+"\n    命中本地清单条目："+term)
			}
		}
	})

	if len(findings) > 0 {
		t.Error("受跟踪文件命中 " + localDenyFile + " 中登记的环境特有标识：\n\n" +
			strings.Join(dedupe(findings), "\n") + "\n\n" +
			"改用中性名称，或把内容移到 local-reports/。")
	}
}

// TestDocumentedPrefixesRejectRealisticAddresses 白名单不能宽到形同虚设。
//
// 用合成地址验证：它们不属于任何真实环境，但形态与真实内网地址一致，
// 必须被拦下。若哪天有人为了让门禁通过而把 10. 整段加进白名单，这里会失败。
func TestDocumentedPrefixesRejectRealisticAddresses(t *testing.T) {
	shouldReject := []string{
		"10.99.12.34", "10.200.1.1", "172.20.5.8", "192.168.77.9",
		"104.18.5.6", "52.84.1.1",
	}
	for _, a := range shouldReject {
		if isDocumented(a) {
			t.Errorf("%q 不应被当作文档用例放行——白名单过宽会让门禁失去意义", a)
		}
	}
}

// TestDocumentedPrefixesAcceptPlaceholders 合法占位不得被误伤。
//
// 门禁误报的代价是它会被关掉，所以放行范围要和拦截范围一样明确。
func TestDocumentedPrefixesAcceptPlaceholders(t *testing.T) {
	shouldAccept := []string{
		"10.0.0.11", "10.0.1.5", "192.168.1.1", "172.16.0.1",
		"127.0.0.1", "0.0.0.0", "169.254.169.254",
		"203.0.113.10", "198.51.100.7", "192.0.2.1", "8.8.8.8",
	}
	for _, a := range shouldAccept {
		if !isDocumented(a) {
			t.Errorf("%q 是标准文档用例，不应被拦——误报会导致门禁被绕过或关闭", a)
		}
	}
}

// TestVersionStringsAreNotTreatedAsAddresses 形似地址的版本号不该报错。
func TestVersionStringsAreNotTreatedAsAddresses(t *testing.T) {
	for _, v := range []string{"1.20.3.4", "2.4.0.1"} {
		if !looksLikeVersion([]byte(v), 0, v) {
			t.Errorf("%q 应被识别为版本号而非地址", v)
		}
	}
	ua := []byte("Chrome/125.0.0.0 Safari")
	if !looksLikeVersion(ua, 7, "125.0.0.0") {
		t.Error("User-Agent 里跟在 / 之后的版本号应被排除")
	}
	if looksLikeVersion([]byte("10.99.12.34"), 0, "10.99.12.34") {
		t.Error("真实形态的地址不应被当成版本号放过")
	}
}

func isDocumented(addr string) bool {
	for _, p := range documentedPrefixes {
		if addr == p || strings.HasPrefix(addr, p) {
			return true
		}
	}
	return false
}

// looksLikeVersion 排除形似地址的版本号。
//
// 两类：首段个位数的四段数字（1.20.3.4 这种语义化版本），
// 以及紧跟在 "/" 之后的（User-Agent 里的 Chrome/125.0.0.0）。
// 后者靠数字本身分辨不出来——125.0.0.0 完全可以是个地址——只能看上下文。
func looksLikeVersion(data []byte, start int, addr string) bool {
	if start > 0 && (data[start-1] == '/' || data[start-1] == '-') {
		return true
	}
	first, _, ok := strings.Cut(addr, ".")
	if !ok {
		return false
	}
	return len(first) == 1 && first != "8" // 8.8.8.8 走白名单，不在此放行
}

// forEachTrackedFile 遍历 git 跟踪的、在扫描范围内的文件内容。
//
// 读工作区而非 git 索引：开发者改完文件重跑 make test 就该看到结果，
// 而不是先 git add 才生效。提交那一刻的把关交给 pre-commit 钩子。
func forEachTrackedFile(t *testing.T, root string, fn func(rel string, data []byte)) {
	t.Helper()
	cmd := exec.Command("git", "ls-files")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("git ls-files 失败（可能不在工作树内），跳过: %v", err)
	}
	for _, rel := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if rel == "" || shouldSkipPath(rel) || !scanExtensions[filepath.Ext(rel)] {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue // 已删除但索引里还在
		}
		fn(rel, data)
	}
}

func shouldSkipPath(rel string) bool {
	for _, p := range skipPaths {
		if strings.HasPrefix(rel, p) {
			return true
		}
	}
	return false
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
