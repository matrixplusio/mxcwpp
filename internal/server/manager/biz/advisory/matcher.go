package advisory

import (
	"fmt"
	"strings"
	"unicode"
)

// DefaultMatcher 实现严格 OS / ecosystem + pkg + arch + version 比对。
//
// 比对规则（必须全部满足）：
//  1. advisory.Ecosystem 非空 → 走 ecosystem gate：host.PkgEcosystem 必须严格相等
//     advisory.Ecosystem 空 → 走 OS gate：advisory.OSFamily 与 host.OSFamily 兼容（rhel ↔ rocky/centos/almalinux 视为兼容）且 OSMajor 相等
//  2. advisory pkg 名 == host pkg 名
//  3. arch 匹配（advisory 为 "noarch" 或 "src" 时跳过 arch 匹配）
//  4. host 版本 < advisory.FixedVersion → 受影响
//
// 双 gate 互斥确保：OS pkg advisory 不会误匹配语言包，语言包 advisory 不会误匹配 OS pkg，
// 跨 OS / 跨生态串台风险归零。
type DefaultMatcher struct{}

// Match 实现 Matcher。
func (m *DefaultMatcher) Match(adv *Advisory, hosts []HostSoftware) []AffectedHost {
	if adv == nil {
		return nil
	}
	var out []AffectedHost
	for _, host := range hosts {
		if !gatePassed(adv, host) {
			continue
		}
		for _, fix := range adv.AffectedPkgs {
			if fix.Name != host.PkgName {
				continue
			}
			if !archMatch(fix.Arch, host.PkgArch) {
				continue
			}
			cmp, err := compareNEVRAOrFallback(host, fix.FixedVersion)
			if err != nil {
				continue
			}
			needs := cmp < 0
			installedDisplay := host.PkgVer
			if installedDisplay == "" {
				installedDisplay = composeNEVRAString(host.PkgEpoch, host.PkgVerRaw, host.PkgRelease)
			}
			out = append(out, AffectedHost{
				HostID:       host.HostID,
				PkgName:      fix.Name,
				InstalledVer: installedDisplay,
				FixedVersion: fix.FixedVersion,
				NeedsUpdate:  needs,
			})
		}
	}
	return out
}

// compareNEVRAOrFallback 优先用 NEVRA 三元组比较，缺字段时退回 PkgVer 字符串比较。
// 按 host.PkgManager 选择 RPM 或 dpkg 比较算法。
//
// 返回 cmp 语义：-1 host < fix(需修)，0 相等(已修)，1 host > fix(已超新)。
func compareNEVRAOrFallback(host HostSoftware, fixedVersion string) (int, error) {
	cmp := selectVersionComparator(host.PkgManager)
	if host.PkgVerRaw != "" {
		installed := composeNEVRAString(host.PkgEpoch, host.PkgVerRaw, host.PkgRelease)
		return cmp(installed, fixedVersion)
	}
	if host.PkgVer != "" {
		return cmp(host.PkgVer, fixedVersion)
	}
	return 0, fmt.Errorf("no version info")
}

// selectVersionComparator 按 pkg manager 选版本比较算法。
func selectVersionComparator(pkgManager string) func(a, b string) (int, error) {
	switch pkgManager {
	case "dpkg":
		return CompareDpkgVersion
	default:
		return CompareRPMVersion
	}
}

// composeNEVRAString 把 epoch/version/release 拼成标准 NEVRA 字符串(无 name 无 arch)。
//
//	epoch="" version="3.5.1" release="3.el9" → "3.5.1-3.el9"
//	epoch="0" version="3.5.1" release="3.el9" → "0:3.5.1-3.el9"
//	epoch="2" version="1.14.0" release="1.el9" → "2:1.14.0-1.el9"
func composeNEVRAString(epoch, version, release string) string {
	out := version
	if release != "" {
		out = out + "-" + release
	}
	if epoch != "" {
		out = epoch + ":" + out
	}
	return out
}

// gatePassed 双 gate 互斥校验：advisory 须经 ecosystem 或 OS 路径其一精确匹配 host。
//
// 拒绝匹配的情况：
//   - advisory 同时声明 Ecosystem 与 OSFamily（数据异常）
//   - advisory 双空（无可识别归属）
//   - Ecosystem 路径下 ecosystem 不严格相等
//   - OS 路径下 OS family/major 不兼容
func gatePassed(adv *Advisory, host HostSoftware) bool {
	switch {
	case adv.Ecosystem != "" && adv.OSFamily != "":
		// 异常 advisory：两个 gate 同时声明，拒绝匹配避免误判
		return false
	case adv.Ecosystem != "":
		return adv.Ecosystem == host.PkgEcosystem
	case adv.OSFamily != "":
		return osCompatible(adv.OSFamily, adv.OSMajorVer, host.OSFamily, host.OSMajor)
	default:
		// 双空 advisory 无法 gate，拒绝匹配
		return false
	}
}

// osCompatible 判断 host OS 是否在 advisory OS 覆盖范围。
//
// RHEL 同源生态视为兼容（advisory.OSFamily="rhel" 覆盖 host.OSFamily in {rhel,rocky,centos,almalinux,oraclelinux}）。
// 其他 OS 必须严格匹配。
func osCompatible(advFamily, advMajor, hostFamily, hostMajor string) bool {
	if advMajor == "" || hostMajor == "" || advMajor != hostMajor {
		return false
	}
	advFamily = strings.ToLower(advFamily)
	hostFamily = strings.ToLower(hostFamily)

	rhelCompat := map[string]bool{
		"rhel":          true,
		"rocky":         true,
		"centos":        true,
		"centos-stream": true,
		"almalinux":     true,
		"oraclelinux":   true,
	}
	if advFamily == "rhel" || advFamily == "rocky" {
		return rhelCompat[hostFamily]
	}
	// 信创 OS：openEuler 衍生兼容(龙蜥 Anolis 基于 openEuler)，
	// 麒麟 V10 / 统信 UOS 视为独立家族（基于不同上游）。
	if advFamily == "openeuler" {
		return hostFamily == "openeuler" || hostFamily == "anolis" || hostFamily == "openanolis"
	}
	return advFamily == hostFamily
}

// archMatch arch 匹配。
// advisory arch 为 "noarch"/"src"/空 → 视为通用，匹配所有 host arch。
func archMatch(advArch, hostArch string) bool {
	if advArch == "" || advArch == "noarch" || advArch == "src" {
		return true
	}
	return advArch == hostArch
}

// rpmVerEpoch 拆分 RPM 版本号。
// 形如 "1:3.5.5-1.el9_4" → epoch=1, ver=3.5.5, rel=1.el9_4
// "3.5.1-3.el9" → epoch=0, ver=3.5.1, rel=3.el9
func rpmVerEpoch(s string) (epoch int, ver, rel string, err error) {
	rest := s
	if colon := strings.Index(rest, ":"); colon > 0 && allDigits(rest[:colon]) {
		for _, c := range rest[:colon] {
			epoch = epoch*10 + int(c-'0')
		}
		rest = rest[colon+1:]
	}
	if dash := strings.LastIndex(rest, "-"); dash > 0 {
		ver = rest[:dash]
		rel = rest[dash+1:]
	} else {
		ver = rest
	}
	if ver == "" {
		err = fmt.Errorf("invalid rpm version: %q", s)
	}
	return
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// CompareRPMVersion 按 RPM 版本比较语义比对 a 和 b。
// 返回 -1 (a<b) / 0 (a==b) / 1 (a>b)。
//
// 实现 rpm-vercmp 算法（简化版）：
//   - 先比 epoch (整数)
//   - 再比 version segment（按数字段+字母段交替比较）
//   - 再比 release segment
//
// 这是商业级 CWPP 核心：不能用 strings.Compare（"10.0" < "9.0" 字符串比是错的）。
func CompareRPMVersion(a, b string) (int, error) {
	aEpoch, aVer, aRel, err := rpmVerEpoch(a)
	if err != nil {
		return 0, err
	}
	bEpoch, bVer, bRel, err := rpmVerEpoch(b)
	if err != nil {
		return 0, err
	}
	if aEpoch != bEpoch {
		if aEpoch < bEpoch {
			return -1, nil
		}
		return 1, nil
	}
	if c := rpmSegmentCompare(aVer, bVer); c != 0 {
		return c, nil
	}
	// version 相同时 release 才参与比较；若一边 release 空，视为相等（不比 release）
	if aRel == "" || bRel == "" {
		return 0, nil
	}
	return rpmSegmentCompare(aRel, bRel), nil
}

// rpmSegmentCompare RPM segment 比对。
// 按数字段 + 字母段交替切分，数字段按数值比较，字母段按 ASCII 比较。
// 例: "3.5.5" 拆为 [3, 5, 5]，与 "3.5.10" 拆为 [3, 5, 10] 比较，10>5 → 后者更大。
func rpmSegmentCompare(a, b string) int {
	for len(a) > 0 || len(b) > 0 {
		a = trimNonAlnum(a)
		b = trimNonAlnum(b)
		if len(a) == 0 && len(b) == 0 {
			return 0
		}
		if len(a) == 0 {
			return -1
		}
		if len(b) == 0 {
			return 1
		}
		aIsNum := unicode.IsDigit(rune(a[0]))
		bIsNum := unicode.IsDigit(rune(b[0]))
		if aIsNum != bIsNum {
			if aIsNum {
				return 1 // 数字 > 字母（rpm 约定）
			}
			return -1
		}
		var aSeg, bSeg string
		if aIsNum {
			aSeg, a = splitDigitPrefix(a)
			bSeg, b = splitDigitPrefix(b)
			// 去 leading zero
			aSeg = strings.TrimLeft(aSeg, "0")
			bSeg = strings.TrimLeft(bSeg, "0")
			if len(aSeg) != len(bSeg) {
				if len(aSeg) < len(bSeg) {
					return -1
				}
				return 1
			}
		} else {
			aSeg, a = splitAlphaPrefix(a)
			bSeg, b = splitAlphaPrefix(b)
		}
		if aSeg < bSeg {
			return -1
		}
		if aSeg > bSeg {
			return 1
		}
	}
	return 0
}

func trimNonAlnum(s string) string {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if unicode.IsLetter(rune(c)) || unicode.IsDigit(rune(c)) {
			return s[i:]
		}
	}
	return ""
}

func splitDigitPrefix(s string) (string, string) {
	for i := 0; i < len(s); i++ {
		if !unicode.IsDigit(rune(s[i])) {
			return s[:i], s[i:]
		}
	}
	return s, ""
}

func splitAlphaPrefix(s string) (string, string) {
	for i := 0; i < len(s); i++ {
		if !unicode.IsLetter(rune(s[i])) {
			return s[:i], s[i:]
		}
	}
	return s, ""
}
