package advisory

import "strings"

// parseCVSSv3Vector 按 CVSS v3.x 算法解析 vector 字符串，返回 Base Score。
//
// 向量示例: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
//
// 算法实现等价 NVD CVSS v3.1 specification:
//   - ISS (Impact Sub Score) = 1 - (1-C)(1-I)(1-A)
//   - Impact: scope unchanged → 6.42*ISS；scope changed → 7.52*(ISS-0.029) - 3.25*(ISS-0.02)^15
//   - Exploitability = 8.22 * AV * AC * PR * UI
//   - Base: scope unchanged → Impact+Exp；scope changed → 1.08*(Impact+Exp)，封顶 10.0，向上 0.1 取整
//
// 解析失败（缺指标）返回 0。
func parseCVSSv3Vector(vector string) float64 {
	metrics := make(map[string]string)
	for _, part := range strings.Split(vector, "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}

	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	ac := map[string]float64{"L": 0.77, "H": 0.44}
	ui := map[string]float64{"N": 0.85, "R": 0.62}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	prU := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	prC := map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}

	avVal, ok1 := av[metrics["AV"]]
	acVal, ok2 := ac[metrics["AC"]]
	uiVal, ok3 := ui[metrics["UI"]]
	cVal, ok4 := cia[metrics["C"]]
	iVal, ok5 := cia[metrics["I"]]
	aVal, ok6 := cia[metrics["A"]]
	scopeChanged := metrics["S"] == "C"

	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
		return 0
	}

	var prVal float64
	if scopeChanged {
		prVal = prC[metrics["PR"]]
	} else {
		prVal = prU[metrics["PR"]]
	}

	iss := 1 - (1-cVal)*(1-iVal)*(1-aVal)
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*cvssPow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0
	}
	exploitability := 8.22 * avVal * acVal * prVal * uiVal

	var base float64
	if scopeChanged {
		base = 1.08 * (impact + exploitability)
	} else {
		base = impact + exploitability
	}
	if base > 10.0 {
		base = 10.0
	}
	return cvssRoundUp(base)
}

func cvssPow(base float64, exp int) float64 {
	result := 1.0
	for i := 0; i < exp; i++ {
		result *= base
	}
	return result
}

func cvssRoundUp(val float64) float64 {
	scaled := val * 10
	truncated := float64(int(scaled))
	if scaled > truncated {
		return (truncated + 1) / 10
	}
	return truncated / 10
}

// scoreToSeverityMid 按 CVSS 数值映射严重度；与 vuln_scanner.mapSeverity 一致：
// 0 分映射为 "medium"（OSV 缺分时保守标记 medium 而非 none）。
func scoreToSeverityMid(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	}
	return SeverityMedium
}

// classifyFromCVSSVectorBasic 由 CVSS vector 推 attack vector + 简单 vuln type。
//
// attack_vector: 由 AV 段直接映射 (N=network / A=adjacent / L=local / P=physical)
// vuln_type:     由 Impact 模式启发式归类（无完整 CWE 时近似），覆盖率有限。
func classifyFromCVSSVectorBasic(vector string) (attackVector, vulnType string) {
	metrics := make(map[string]string)
	for _, part := range strings.Split(vector, "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}
	switch metrics["AV"] {
	case "N":
		attackVector = "network"
	case "A":
		attackVector = "adjacent"
	case "L":
		attackVector = "local"
	case "P":
		attackVector = "physical"
	}
	// 启发式 vuln type
	switch {
	case metrics["C"] == "H" && metrics["I"] == "N" && metrics["A"] == "N":
		vulnType = "info-disclosure"
	case metrics["C"] == "N" && metrics["I"] == "N" && metrics["A"] == "H":
		vulnType = "dos"
	case metrics["I"] == "H" && metrics["UI"] == "R":
		vulnType = "injection"
	}
	return
}
