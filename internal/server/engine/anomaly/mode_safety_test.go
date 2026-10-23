package anomaly

import (
	"testing"

	"go.uber.org/zap"
)

// TestNormalizeModeSafeDefault 校验缺配置/非法值一律回落 shadow（绝不 context/alert），
// 合法值原样保留。
func TestNormalizeModeSafeDefault(t *testing.T) {
	for _, s := range []string{"", "bogus", "CONTEXT", "Alert", "on"} {
		if got := normalizeMode(s); got != ModeShadow {
			t.Errorf("normalizeMode(%q)=%q, 非法/缺失应回落 shadow", s, got)
		}
	}
	for _, m := range []Mode{ModeOff, ModeShadow, ModeContext, ModeAlert} {
		if got := normalizeMode(string(m)); got != m {
			t.Errorf("normalizeMode(%q)=%q, 合法值应原样保留", m, got)
		}
	}
}

// TestLoadModeNilDBShadow 校验 db=nil 时 LoadMode 回落 shadow（不写正式告警）。
func TestLoadModeNilDBShadow(t *testing.T) {
	if got := LoadMode(nil, zap.NewNop()); got != ModeShadow {
		t.Errorf("LoadMode(nil)=%q, 应回落 shadow", got)
	}
}

// TestNewDetectorDefaultShadow 校验检测器构造即为安全默认：shadow + schema 未就绪，
// 生效模式 shadow（只观测不落库）。
func TestNewDetectorDefaultShadow(t *testing.T) {
	d := NewDetector(nil, nil, zap.NewNop())
	st := d.Status()
	if st.Mode != ModeShadow {
		t.Errorf("默认 Mode=%q, 应 shadow", st.Mode)
	}
	if st.SchemaReady {
		t.Error("默认 schema 应未就绪")
	}
	if st.EffectiveMode != ModeShadow {
		t.Errorf("默认 EffectiveMode=%q, 应 shadow", st.EffectiveMode)
	}
}

// TestEffectiveModeFailClosed 校验 fail-closed：schema 未就绪时，一切会落库的模式(context/alert)
// 生效降级为 shadow（只观测不落库）、严重度封顶 high；off 保持 off。schema 就绪后才恢复配置模式。
func TestEffectiveModeFailClosed(t *testing.T) {
	ceiling := func(d *Detector) string {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.officialCeilingLocked()
	}

	d := NewDetector(nil, nil, zap.NewNop())

	// schema 未就绪：context/alert 均降级 shadow，ceiling 封顶 high。
	for _, m := range []Mode{ModeContext, ModeAlert} {
		d.SetMode(m)
		if got := d.EffectiveMode(); got != ModeShadow {
			t.Errorf("schema 未就绪 + %q：EffectiveMode=%q, 应 fail-closed 到 shadow", m, got)
		}
		if c := ceiling(d); c != "high" {
			t.Errorf("schema 未就绪 + %q：ceiling=%q, 应封顶 high", m, c)
		}
	}

	// off 恒为 off（不做任何事），不受 schema gate 影响。
	d.SetMode(ModeOff)
	if got := d.EffectiveMode(); got != ModeOff {
		t.Errorf("off 应保持 off, got %q", got)
	}

	// schema 就绪后恢复配置模式；alert 才允许 critical。
	d.mu.Lock()
	d.schemaReady = true
	d.mu.Unlock()
	d.SetMode(ModeContext)
	if got := d.EffectiveMode(); got != ModeContext {
		t.Errorf("schema 就绪 + context：EffectiveMode=%q, 应 context", got)
	}
	if c := ceiling(d); c != "high" {
		t.Errorf("context 就绪：ceiling=%q, 应封顶 high（非 alert 不判 critical）", c)
	}
	d.SetMode(ModeAlert)
	if got := d.EffectiveMode(); got != ModeAlert {
		t.Errorf("schema 就绪 + alert：EffectiveMode=%q, 应 alert", got)
	}
	if c := ceiling(d); c != "critical" {
		t.Errorf("alert 就绪：ceiling=%q, 应允许 critical", c)
	}
}

// TestPersistEligibility 校验落库资格是正向白名单：仅生效 context/alert 允许落库，
// off/shadow 及 schema 未就绪的降级一律禁止 —— 防止 SetMode 并发切 off 后仍 upsert。
func TestPersistEligibility(t *testing.T) {
	eligible := func(d *Detector) bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.persistEligibleLocked()
	}

	d := NewDetector(nil, nil, zap.NewNop())

	// schema 未就绪：任何模式都不得落库（context/alert 降级 shadow，off/shadow 本就不落）。
	for _, m := range []Mode{ModeOff, ModeShadow, ModeContext, ModeAlert} {
		d.SetMode(m)
		if eligible(d) {
			t.Errorf("schema 未就绪 + %q：不应有落库资格", m)
		}
	}

	// schema 就绪后：off/shadow 仍不落库；context/alert 才落库。
	d.mu.Lock()
	d.schemaReady = true
	d.mu.Unlock()
	for _, tc := range []struct {
		mode Mode
		want bool
	}{
		{ModeOff, false},
		{ModeShadow, false},
		{ModeContext, true},
		{ModeAlert, true},
	} {
		d.SetMode(tc.mode)
		if got := eligible(d); got != tc.want {
			t.Errorf("schema 就绪 + %q：落库资格=%v, 期望 %v", tc.mode, got, tc.want)
		}
	}
}

// TestDNSGate 校验 M0 DNS 闸：recon 整体禁用、dns_unique_domain/dns_nx_ratio 判为不可信维，
// dns_query_count 仍可信。
func TestDNSGate(t *testing.T) {
	if !patternRequiresDNSFields("reconnaissance") {
		t.Error("recon 依赖 DNS 枚举，M0 应整体禁用")
	}
	for _, p := range []string{"c2_beacon", "data_exfiltration", "privilege_escalation"} {
		if patternRequiresDNSFields(p) {
			t.Errorf("%q 不应被 DNS 闸整体禁用", p)
		}
	}
	if !dnsFieldInvalidIndex(11) || !dnsFieldInvalidIndex(12) {
		t.Error("dns_unique_domain(11)/dns_nx_ratio(12) 应判为不可信维")
	}
	if dnsFieldInvalidIndex(10) {
		t.Error("dns_query_count(10) 只是计数，应仍可信")
	}
}
