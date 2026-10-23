package intrusion

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// 用标注语料里的**正常样本**检验入侵检测器的误报面。
//
// 这些 detector 有真实算法但从未接线，也没有任何测试。接线前必须先回答一个问题：
// 它们会不会对日常运维行为报警。一个会在每次发布时刷屏的检测，
// 上线后的结果不是「多发现威胁」，而是没人再看这个告警源。
//
// 语料复用检测回放的标注集：正常样本刻意选的是「长得像攻击的日常运维」，
// 例如配置管理派生 shell、包管理器投放 systemd 单元、日志轮转批量删日志。

type corpusSample struct {
	Name      string            `json:"name"`
	Label     string            `json:"label"`
	Technique string            `json:"technique"`
	DataType  int32             `json:"data_type"`
	Fields    map[string]string `json:"fields"`
	Note      string            `json:"note"`
}

func loadBenignSamples(t *testing.T) []corpusSample {
	t.Helper()
	dir := filepath.Join("..", "celengine", "replay", "testdata", "corpus")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("语料目录不可读: %v", err)
	}
	var out []corpusSample
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("读取 %s: %v", e.Name(), err)
		}
		var doc struct {
			Samples []corpusSample `json:"samples"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("解析 %s: %v", e.Name(), err)
		}
		for _, s := range doc.Samples {
			if s.Label == "benign" {
				out = append(out, s)
			}
		}
	}
	if len(out) == 0 {
		t.Skip("语料里没有正常样本")
	}
	return out
}

// RootkitDetector 对正常运维行为的误报面。
//
// 已知风险点：它的模式里含 `systemctl (enable|start) .*\.service` 与
// `/etc/systemd/system/.*\.service`——前者每次正常发布都会命中，
// 后者包管理器装包就会命中。本测试把这件事量化出来，而不是留给上线后发现。
func TestRootkitDetector_BenignCorpus(t *testing.T) {
	d := NewRootkitDetector()
	samples := loadBenignSamples(t)

	var flagged []corpusSample
	for _, s := range samples {
		content := s.Fields["cmdline"]
		if content == "" {
			content = s.Fields["file_path"]
		}
		if content == "" {
			continue
		}
		if _, hit := d.Scan(context.Background(), IndicatorEvent{
			HostID: "h1", Source: "process", Content: content,
			ExePath: s.Fields["exe"],
		}); hit {
			flagged = append(flagged, s)
		}
	}

	for _, s := range flagged {
		t.Errorf("正常样本被判为 rootkit 指标：%s\n  为什么它是正常的：%s", s.Name, s.Note)
	}
	if len(flagged) > 0 {
		t.Fatalf("RootkitDetector 在 %d/%d 条正常样本上误命中——接线前必须先收窄模式",
			len(flagged), len(samples))
	}
}

// WebshellDetector 对正常运维行为的误报面。
func TestWebshellDetector_BenignCorpus(t *testing.T) {
	d := NewWebshellDetector()
	samples := loadBenignSamples(t)

	var flagged []corpusSample
	for _, s := range samples {
		content := s.Fields["cmdline"]
		if content == "" {
			content = s.Fields["file_path"]
		}
		if content == "" {
			continue
		}
		if _, hit := d.Scan(context.Background(), FileSampleEvent{
			HostID: "h1", FilePath: s.Fields["file_path"], Content: content,
		}); hit {
			flagged = append(flagged, s)
		}
	}

	for _, s := range flagged {
		t.Errorf("正常样本被判为 webshell：%s\n  为什么它是正常的：%s", s.Name, s.Note)
	}
	if len(flagged) > 0 {
		t.Fatalf("WebshellDetector 在 %d/%d 条正常样本上误命中", len(flagged), len(samples))
	}
}

// ReverseShellDetector 对正常运维行为的误报面。
func TestReverseShellDetector_BenignCorpus(t *testing.T) {
	d := NewReverseShellDetector()
	samples := loadBenignSamples(t)

	var flagged []corpusSample
	for _, s := range samples {
		cmd := s.Fields["cmdline"]
		if cmd == "" {
			continue
		}
		if _, hit := d.Scan(context.Background(), ProcessEvent{
			HostID: "h1", Cmdline: cmd, ExePath: s.Fields["exe"],
		}); hit {
			flagged = append(flagged, s)
		}
	}

	for _, s := range flagged {
		t.Errorf("正常样本被判为反弹 shell：%s\n  为什么它是正常的：%s", s.Name, s.Note)
	}
	if len(flagged) > 0 {
		t.Fatalf("ReverseShellDetector 在 %d/%d 条正常样本上误命中", len(flagged), len(samples))
	}
}

// 排除包管理器不能把检测能力一起排除掉。
//
// 只测「不误报」的话，一个恒不命中的实现也能满分。攻击者投放持久化单元
// 用的是 shell 或脚本解释器，不是 dpkg——这个区别正是排除逻辑的依据，
// 也必须被验证。
func TestRootkitDetector_StillCatchesRealPersistence(t *testing.T) {
	d := NewRootkitDetector()

	cases := []struct {
		name    string
		content string
		exe     string
	}{
		{"shell 投放 systemd 单元", "/etc/systemd/system/update-notifier.service", "/bin/bash"},
		{"脚本解释器写 cron", "/etc/cron.d/backdoor", "/usr/bin/python3"},
		{"执行体未知时不放行", "/etc/systemd/system/evil.service", ""},
	}
	for _, c := range cases {
		if _, hit := d.Scan(context.Background(), IndicatorEvent{
			HostID: "h1", Source: "file", Content: c.content, ExePath: c.exe,
		}); !hit {
			t.Errorf("%s：应当检出，实际未命中（content=%q exe=%q）", c.name, c.content, c.exe)
		}
	}
}

// 包管理器豁免只覆盖 cron / systemd 两类。
//
// LKM 加载、LD_PRELOAD、authorized_keys 写入这三类，包管理器本来就不会做，
// 一旦出现就是异常——豁免不该扩大到它们身上。
func TestRootkitDetector_PackageManagerExemptionIsNarrow(t *testing.T) {
	d := NewRootkitDetector()

	cases := []struct{ name, content string }{
		{"LKM rootkit", "insmod /tmp/diamorphine.ko"},
		{"LD_PRELOAD", "LD_PRELOAD=/tmp/evil.so"},
		{"authorized_keys 写入", "echo ssh-rsa AAAA >> /root/.ssh/authorized_keys"},
	}
	for _, c := range cases {
		// 即便声称是包管理器产生的，这三类仍应命中
		if _, hit := d.Scan(context.Background(), IndicatorEvent{
			HostID: "h1", Source: "process", Content: c.content, ExePath: "/usr/bin/dpkg",
		}); !hit {
			t.Errorf("%s：包管理器豁免不该覆盖这一类，但未命中", c.name)
		}
	}
}

// 语料里的攻击样本必须被对应检测器认出来。
//
// 这些 detector 从未接线也从未被验证过。接线前至少要证明它们对已知攻击有效，
// 否则接上去的是一个不响的检测——比不接更糟，因为它会让人以为这块已经覆盖了。
func TestDetectors_CatchAttackSamples(t *testing.T) {
	dir := filepath.Join("..", "celengine", "replay", "testdata", "corpus")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("语料目录不可读: %v", err)
	}
	var attacks []corpusSample
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		var doc struct {
			Samples []corpusSample `json:"samples"`
		}
		if json.Unmarshal(data, &doc) != nil {
			continue
		}
		for _, s := range doc.Samples {
			if s.Label == "attack" {
				attacks = append(attacks, s)
			}
		}
	}

	rev := NewReverseShellDetector()
	rk := NewRootkitDetector()

	var caught int
	for _, s := range attacks {
		cmd := s.Fields["cmdline"]
		fp := s.Fields["file_path"]
		content := cmd
		if content == "" {
			content = fp
		}
		hit := false
		if cmd != "" {
			if _, ok := rev.Scan(context.Background(), ProcessEvent{
				HostID: "h1", Cmdline: cmd, ExePath: s.Fields["exe"],
			}); ok {
				hit = true
			}
		}
		if !hit && content != "" {
			if _, ok := rk.Scan(context.Background(), IndicatorEvent{
				HostID: "h1", Source: "file", Content: content, ExePath: s.Fields["exe"],
			}); ok {
				hit = true
			}
		}
		if hit {
			caught++
		} else {
			t.Logf("未检出: %s (%s) — %s", s.Name, s.Technique, s.Note)
		}
	}
	t.Logf("入侵检测器覆盖攻击样本: %d/%d", caught, len(attacks))

	// 不设具体门槛：这两个 detector 本就不针对全部技术。
	// 但一条都检不出说明它们根本没工作，那样接线毫无意义。
	if caught == 0 {
		t.Fatal("入侵检测器对全部攻击样本都无反应——接线前必须先查清原因")
	}
}

// PrivEscalationDetector 对正常运维行为的误报面。
//
// 提权检测最容易踩的坑是把 sudo 本身当信号——运维每天都在用 sudo。
func TestPrivEscalationDetector_BenignCorpus(t *testing.T) {
	d := NewPrivEscalationDetector()
	samples := loadBenignSamples(t)

	var flagged []corpusSample
	for _, s := range samples {
		cmd := s.Fields["cmdline"]
		if cmd == "" {
			continue
		}
		if _, hit := d.Scan(context.Background(), ProcessEvent{
			HostID: "h1", Cmdline: cmd, ExePath: s.Fields["exe"],
		}); hit {
			flagged = append(flagged, s)
		}
	}
	for _, s := range flagged {
		t.Errorf("正常样本被判为提权：%s\n  为什么它是正常的：%s", s.Name, s.Note)
	}
	if len(flagged) > 0 {
		t.Fatalf("PrivEscalationDetector 在 %d/%d 条正常样本上误命中", len(flagged), len(samples))
	}
}

// BruteForceDetector 的滑窗行为：单次失败不告警，连续失败才告警。
//
// 语料里没有登录事件，所以直接构造。这个检测的核心风险不是模式匹配，
// 而是阈值——设得太低会把用户输错一次密码当成攻击。
func TestBruteForceDetector_ThresholdBehaviour(t *testing.T) {
	d := NewBruteForceDetector(0, 0) // 0 表示用默认窗口与阈值
	ctx := context.Background()

	att := LoginAttempt{
		HostID: "h1", SourceIP: "10.0.0.5", Username: "deploy", Success: false,
	}

	// 单次失败不该告警——输错一次密码是日常
	if res := d.Ingest(ctx, att); res.BruteForce != nil {
		t.Fatal("单次登录失败不该告警")
	}

	// 成功登录应清除计数：合法用户重试成功后，之前的失败不该继续累积
	for range 3 {
		d.Ingest(ctx, att)
	}
	ok := att
	ok.Success = true
	if res := d.Ingest(ctx, ok); res.BruteForce != nil || res.SuccessAfterFailures != nil {
		t.Fatal("输错几次再输对是常态，成功登录本身不该告警")
	}
	if res := d.Ingest(ctx, att); res.BruteForce != nil {
		t.Fatal("成功登录应清除失败计数，之后单次失败不该立即告警")
	}
}

// 主机侧会把同一来源的连续失败合并成一条、带上次数。按条数算的话，
// 一分钟几百次的爆破在这里只算一两次，永远到不了阈值。
func TestBruteForceDetector_CountsCoalescedFailures(t *testing.T) {
	d := NewBruteForceDetector(0, 0)
	res := d.Ingest(context.Background(), LoginAttempt{HostID: "h1", SourceIP: "203.0.113.9", Username: "root", Count: 40})
	if res.BruteForce == nil {
		t.Fatal("一条合并了 40 次失败的记录应直接达到阈值")
	}
}

// 爆破之后同一来源登录成功：这是失陷，不是「用户终于输对了」。
func TestBruteForceDetector_SuccessAfterFailures(t *testing.T) {
	ctx := context.Background()
	t0 := time.Unix(1760000000, 0)
	fail := func(d *BruteForceDetector, ip string, n int, at time.Time) BruteForceResult {
		return d.Ingest(ctx, LoginAttempt{HostID: "h1", SourceIP: ip, Username: "root", Count: n, Timestamp: at})
	}
	success := func(d *BruteForceDetector, ip string, at time.Time) BruteForceResult {
		return d.Ingest(ctx, LoginAttempt{HostID: "h1", SourceIP: ip, Username: "root", Success: true, Timestamp: at})
	}

	// 失败累计够多但还没到下一次告警，随后成功。
	d := NewBruteForceDetector(0, 0)
	if res := fail(d, "203.0.113.9", BruteForceThreshold, t0); res.BruteForce == nil {
		t.Fatal("应先报暴力破解")
	}
	fail(d, "203.0.113.9", 2, t0.Add(time.Minute))
	if res := success(d, "203.0.113.9", t0.Add(2*time.Minute)); res.SuccessAfterFailures == nil {
		t.Fatal("爆破告警之后登录成功应单独报出")
	}
	// 报过之后清零：同一来源紧接着的正常登录不再重复报。
	if res := success(d, "203.0.113.9", t0.Add(3*time.Minute)); res.SuccessAfterFailures != nil {
		t.Fatal("同一次得手不该重复报")
	}

	// 别的来源的失败不算到这个来源头上。
	d = NewBruteForceDetector(0, 0)
	fail(d, "198.51.100.7", 50, t0)
	if res := success(d, "10.0.0.5", t0.Add(time.Minute)); res.SuccessAfterFailures != nil {
		t.Fatal("另一个来源的爆破不该牵连正常登录")
	}

	// 爆破过去很久之后的登录不再关联。
	d = NewBruteForceDetector(0, 0)
	fail(d, "203.0.113.9", 50, t0)
	if res := success(d, "203.0.113.9", t0.Add(bruteAlertedTTL+time.Minute)); res.SuccessAfterFailures != nil {
		t.Fatal("超过关联时限的登录不该再算爆破得手")
	}
}

// 只来一次就不再出现的来源要能被清掉，表不随来源数无限增长。
func TestBruteForceDetector_PrunesIdleSources(t *testing.T) {
	d := NewBruteForceDetector(0, 0)
	ctx := context.Background()
	t0 := time.Unix(1760000000, 0)
	for i := 0; i < 1000; i++ {
		d.Ingest(ctx, LoginAttempt{HostID: "h1", SourceIP: "198.51.100." + strconv.Itoa(i), Username: "root", Timestamp: t0})
	}
	d.Ingest(ctx, LoginAttempt{HostID: "h1", SourceIP: "203.0.113.9", Username: "root", Timestamp: t0.Add(BruteForceWindow + 2*time.Minute)})
	if n := len(d.attempts); n != 1 {
		t.Fatalf("过期的来源应被清掉，表里还有 %d 项", n)
	}
}

// 生产上的时钟：事件自带的时间不参与判断。
//
// 一台主机报一批时间在将来的失败，不能让它们永不过期；报的时间在过去（时钟落后、落盘后补发），
// 也不能一进来就被当成过期。
func TestBruteForceDetector_IgnoresHostReportedTime(t *testing.T) {
	wall := time.Unix(1760000000, 0)
	orig := bruteClock
	defer func() { bruteClock = orig }()
	bruteClock = func(LoginAttempt) time.Time { return wall } // 与生产一致：不看 att.Timestamp

	ctx := context.Background()
	d := NewBruteForceDetector(0, 0)
	// 时间在一年之后的一批失败：照常计数、照常告警，之后照常过期。
	var res BruteForceResult
	for i := 0; i < BruteForceThreshold; i++ {
		res = d.Ingest(ctx, LoginAttempt{HostID: "h2", SourceIP: "198.51.100.7", Username: "root", Timestamp: wall.Add(365 * 24 * time.Hour)})
	}
	if res.BruteForce == nil {
		t.Fatal("时间在将来的失败也应按到达时间计数")
	}
	d.Ingest(ctx, LoginAttempt{HostID: "h2", SourceIP: "198.51.100.8", Username: "root", Timestamp: wall.Add(365 * 24 * time.Hour)})
	wall = wall.Add(bruteAlertedTTL + BruteForceWindow + 2*time.Minute)
	d.Ingest(ctx, LoginAttempt{HostID: "h1", SourceIP: "203.0.113.9", Username: "root"})
	if len(d.attempts) != 1 || len(d.alerted) != 0 {
		t.Fatalf("报了将来时间的记录应照常过期：attempts=%d alerted=%d", len(d.attempts), len(d.alerted))
	}

	// 时间落后十分钟、每 20 秒失败一次：不能因为「看起来早就过期」而数不到。
	d = NewBruteForceDetector(0, 0)
	res = BruteForceResult{}
	for i := 0; i < BruteForceThreshold; i++ {
		wall = wall.Add(20 * time.Second)
		res = d.Ingest(ctx, LoginAttempt{HostID: "h3", SourceIP: "203.0.113.50", Username: "root", Timestamp: wall.Add(-10 * time.Minute)})
	}
	if res.BruteForce == nil {
		t.Fatal("主机时钟落后时爆破仍应被数到")
	}
}

func TestBruteReason(t *testing.T) {
	att := LoginAttempt{SourceIP: "203.0.113.9", Service: "sshd", Username: "root"}
	if got := bruteReason(att, 5, 300); got != "来源 203.0.113.9 在 300 秒内 sshd 登录失败 5 次，最近尝试的账号是 root" {
		t.Errorf("带账号：%q", got)
	}
	att.Username = ""
	if got := bruteReason(att, 7, 300); got != "来源 203.0.113.9 在 300 秒内 sshd 登录失败 7 次" {
		t.Errorf("不带账号：%q", got)
	}
}

func TestParseLoginAttempt(t *testing.T) {
	att := ParseLoginAttempt("h1", map[string]string{
		"event_type": AuthEventLoginFailed, "source_ip": "203.0.113.9", "username": "admin",
		"count": "12", "timestamp": "1760000000", "service": "sshd",
	})
	if att == nil || att.Success || att.Count != 12 || att.Timestamp.Unix() != 1760000000 || att.SourceIP != "203.0.113.9" {
		t.Fatalf("失败登录解析不对：%+v", att)
	}
	if att := ParseLoginAttempt("h1", map[string]string{"event_type": AuthEventLoginSuccess, "source_ip": "10.0.0.5"}); att == nil || !att.Success || att.Count != 1 {
		t.Fatalf("成功登录解析不对：%+v", att)
	}
	for name, f := range map[string]map[string]string{
		"别的事件类型": {"event_type": "auth_sudo", "source_ip": "10.0.0.5"},
		"没有来源地址": {"event_type": AuthEventLoginFailed},
		"只有日志原文": {"log_msg": "Accepted password for root from 10.0.0.1 port 22 ssh2", "source_ip": "10.0.0.1"},
	} {
		if att := ParseLoginAttempt("h1", f); att != nil {
			t.Errorf("%s：不该解析出登录尝试 %+v", name, att)
		}
	}
}

// AbnormalLoginDetector 的冷启动行为。
//
// 它按主机维护画像（国家 / 时段 / IP 段 / 用户），任何「首次见到」都算异常，
// 而画像是进程内空 map 起步。没有学习期时，engine 启动后每台主机的第一次登录
// 都会同时命中「新国家 + 新 IP 段 + 新用户」三条 —— 机群有多少台就报多少条，
// 且每次重启重演。
//
// 学习期把这段静默掉：期内照常喂画像，不产告警。
func TestAbnormalLoginDetector_ColdStartIsSilentDuringLearning(t *testing.T) {
	d := NewAbnormalLoginDetector()
	ctx := context.Background()

	// 一次完全正常的工作时间登录，来自公司出口 IP
	login := SuccessfulLogin{
		HostID:    "h1",
		Username:  "deploy",
		SourceIP:  "10.0.0.5",
		Country:   "CN",
		Timestamp: time.Date(2026, 8, 4, 14, 30, 0, 0, time.UTC), // 下午 2 点半
	}

	if _, hit := d.Ingest(ctx, login); hit {
		t.Fatal("冷启动首次登录仍告警：学习期没生效，接线即刷屏")
	}
	if _, hit := d.Ingest(ctx, login); hit {
		t.Error("第二次相同登录告警，画像没生效")
	}

	if st := d.Stats(); st.HostsLearning != 1 || st.HostsGraduated != 0 {
		t.Errorf("学习期统计不对: %+v", st)
	}
}

// 走完学习期之后，检测必须真的生效——否则「不误报」是靠彻底不告警换来的。
func TestAbnormalLoginDetector_AlertsAfterLearningWindow(t *testing.T) {
	d := NewAbnormalLoginDetector()
	ctx := context.Background()
	base := time.Date(2026, 8, 4, 14, 0, 0, 0, time.UTC)

	// 学习期内的日常登录：同一用户、同一网段、工作时间，每天一次
	for i := 0; i < DefaultLearningMinSamples; i++ {
		login := SuccessfulLogin{
			HostID:    "h1",
			Username:  "deploy",
			SourceIP:  "10.0.0.5",
			Country:   "CN",
			Timestamp: base.Add(time.Duration(i) * 24 * time.Hour),
		}
		if _, hit := d.Ingest(ctx, login); hit {
			t.Fatalf("学习期第 %d 次登录告警了", i+1)
		}
	}

	// 学习期已过（样本数与时长都满足）：来自陌生国家、陌生网段的凌晨登录
	evil := SuccessfulLogin{
		HostID:    "h1",
		Username:  "root",
		SourceIP:  "203.0.113.9",
		Country:   "RU",
		Timestamp: base.Add(DefaultLearningWindow + 5*time.Hour), // 凌晨 3 点
	}
	payload, hit := d.Ingest(ctx, evil)
	if !hit {
		t.Fatal("学习期结束后仍不告警：检测等于没接")
	}
	if len(payload) == 0 {
		t.Error("告警 payload 为空")
	}

	if st := d.Stats(); st.HostsGraduated != 1 {
		t.Errorf("主机应已走完学习期: %+v", st)
	}
}

// 时长与样本数是「都要满足」，各堵一种误报。
func TestAbnormalLoginDetector_LearningNeedsBothTimeAndSamples(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 8, 4, 14, 0, 0, 0, time.UTC)

	// 样本够但时长不够：一天内登录 20 次的机器，画像还没见过周末形态
	t.Run("samples enough, window not elapsed", func(t *testing.T) {
		d := NewAbnormalLoginDetectorWithWindow(7*24*time.Hour, 5)
		for i := 0; i < 20; i++ {
			login := SuccessfulLogin{
				HostID: "h1", Username: "deploy", SourceIP: "10.0.0.5", Country: "CN",
				Timestamp: base.Add(time.Duration(i) * time.Minute),
			}
			d.Ingest(ctx, login)
		}
		evil := SuccessfulLogin{
			HostID: "h1", Username: "root", SourceIP: "203.0.113.9", Country: "RU",
			Timestamp: base.Add(time.Hour),
		}
		if _, hit := d.Ingest(ctx, evil); hit {
			t.Error("时长未到就告警了")
		}
	})

	// 时长够但样本不够：一周只登录两次的低频机器，画像太稀疏
	t.Run("window elapsed, samples too few", func(t *testing.T) {
		d := NewAbnormalLoginDetectorWithWindow(7*24*time.Hour, 10)
		for i := 0; i < 2; i++ {
			login := SuccessfulLogin{
				HostID: "h1", Username: "deploy", SourceIP: "10.0.0.5", Country: "CN",
				Timestamp: base.Add(time.Duration(i) * 72 * time.Hour),
			}
			d.Ingest(ctx, login)
		}
		normal := SuccessfulLogin{
			HostID: "h1", Username: "ops", SourceIP: "10.0.9.7", Country: "CN",
			Timestamp: base.Add(10 * 24 * time.Hour),
		}
		if _, hit := d.Ingest(ctx, normal); hit {
			t.Error("样本不足就告警了：低频主机的第三次登录被当成异常")
		}
	})
}

// 学习期不允许被配置成零，那等同于回到冷启动刷屏。
func TestAbnormalLoginDetector_RejectsZeroLearningWindow(t *testing.T) {
	d := NewAbnormalLoginDetectorWithWindow(0, 0)
	ctx := context.Background()
	login := SuccessfulLogin{
		HostID: "h1", Username: "deploy", SourceIP: "10.0.0.5", Country: "CN",
		Timestamp: time.Date(2026, 8, 4, 14, 0, 0, 0, time.UTC),
	}
	if _, hit := d.Ingest(ctx, login); hit {
		t.Error("学习期被配置成零后冷启动又刷屏了")
	}
}

// 接线前的最后一道闸：走完学习期的主机，日常运维登录必须零告警。
//
// 这个检测每命中一次就是一条 medium 告警送到值班面前。若日常登录也报，
// 结果不是「多发现威胁」，而是没人再看这个告警源。
func TestAbnormalLoginDetector_BenignOpsLoginsAfterGraduation(t *testing.T) {
	d := NewAbnormalLoginDetector()
	ctx := context.Background()
	base := time.Date(2026, 8, 4, 14, 0, 0, 0, time.UTC) // 周二下午 2 点

	for i := 0; i < DefaultLearningMinSamples; i++ {
		if _, hit := d.Ingest(ctx, SuccessfulLogin{
			HostID: "h1", Username: "deploy", SourceIP: "10.0.0.5", Country: "CN",
			Timestamp: base.Add(time.Duration(i) * 24 * time.Hour),
		}); hit {
			t.Fatalf("学习期第 %d 次登录告警了", i+1)
		}
	}
	after := base.Add(DefaultLearningWindow + 3*24*time.Hour)

	benign := []struct {
		name  string
		note  string
		login SuccessfulLogin
	}{
		{
			name:  "同一运维、同一出口 IP 的例行登录",
			note:  "画像里已有的全部维度",
			login: SuccessfulLogin{Username: "deploy", SourceIP: "10.0.0.5", Country: "CN", Timestamp: after},
		},
		{
			name:  "同一出口网段换了台跳板机",
			note:  "IP 维按 /24 聚合，末位变化属常态",
			login: SuccessfulLogin{Username: "deploy", SourceIP: "10.0.0.87", Country: "CN", Timestamp: after.Add(time.Hour)},
		},
		{
			name:  "周末值班登录",
			note:  "时间维只看小时，不看星期几",
			login: SuccessfulLogin{Username: "deploy", SourceIP: "10.0.0.5", Country: "CN", Timestamp: after.Add(4 * 24 * time.Hour)},
		},
		{
			name:  "加班到晚上 11 点",
			note:  "工作时间之外但不在 0-5 点，不该报",
			login: SuccessfulLogin{Username: "deploy", SourceIP: "10.0.0.5", Country: "CN", Timestamp: after.Add(9 * time.Hour)},
		},
		{
			name:  "清早 7 点上线窗口",
			note:  "紧邻 0-5 点边界，边界必须是闭区间之外",
			login: SuccessfulLogin{Username: "deploy", SourceIP: "10.0.0.5", Country: "CN", Timestamp: after.Add(17 * time.Hour)},
		},
	}

	for _, c := range benign {
		login := c.login
		login.HostID = "h1"
		if payload, hit := d.Ingest(ctx, login); hit {
			t.Errorf("日常运维登录被判异常：%s\n  为什么它是正常的：%s\n  告警：%s",
				c.name, c.note, payload)
		}
	}
}

// 0-5 点登录是有意保留的信号，但对常态化的夜间运维会自己闭嘴。
//
// 这是这个检测已知的误报面：值班第一次凌晨登录会报。代价可接受的前提是它
// 不会一直报——同一时段第 3 次之后画像认了这个习惯。
func TestAbnormalLoginDetector_NightLoginHabituates(t *testing.T) {
	d := NewAbnormalLoginDetector()
	ctx := context.Background()
	base := time.Date(2026, 8, 4, 3, 0, 0, 0, time.UTC) // 凌晨 3 点

	// 学习期内的夜间运维：静默，但画像照常记住这个时段。
	for i := 0; i < DefaultLearningMinSamples; i++ {
		if _, hit := d.Ingest(ctx, SuccessfulLogin{
			HostID: "h1", Username: "oncall", SourceIP: "10.0.0.5", Country: "CN",
			Timestamp: base.Add(time.Duration(i) * 24 * time.Hour),
		}); hit {
			t.Fatalf("学习期第 %d 次夜间登录告警了", i+1)
		}
	}

	// 毕业后同一时段的夜间登录不该再报——习惯已被画像认下。
	if payload, hit := d.Ingest(ctx, SuccessfulLogin{
		HostID: "h1", Username: "oncall", SourceIP: "10.0.0.5", Country: "CN",
		Timestamp: base.Add(DefaultLearningWindow + 5*24*time.Hour),
	}); hit {
		t.Errorf("常态化的夜间值班登录仍在告警，值班会被这条噪声淹没：%s", payload)
	}
}

// 进程事件里提到 cron/systemd 路径不是持久化证据。
//
// 按「命令行里出现 cron 目录路径」判定会在几乎每台主机上误报 critical：
// anacron 每小时调用 `basename /etc/cron.hourly/0anacron`，遍历、取路径名、查找也都会出现它。
// 包管理器豁免挡不住这类：执行体是 basename 而不是 rpm。
//
// 放行进程来源不损失检测：投放持久化文件必然产生文件事件，
// 由下面 TestRootkitDetector_StillCatchesRealPersistence 覆盖。
func TestRootkitDetector_ProcessMentioningPathIsNotPersistence(t *testing.T) {
	d := NewRootkitDetector()

	cases := []struct{ name, content, exe string }{
		{"anacron 每小时任务", "basename /etc/cron.hourly/0anacron", "/usr/bin/basename"},
		{"run-parts 遍历 cron 目录", "run-parts --report /etc/cron.daily", "/usr/bin/run-parts"},
		{"查找 systemd 单元", "find /etc/systemd/system -name '*.service'", "/usr/bin/find"},
		{"列目录", "ls -la /etc/cron.d/", "/usr/bin/ls"},
	}
	for _, c := range cases {
		if _, hit := d.Scan(context.Background(), IndicatorEvent{
			HostID: "h1", Source: SourceProcess, Content: c.content, ExePath: c.exe,
		}); hit {
			t.Errorf("%s：进程提到路径不构成持久化证据，不应命中（content=%q）", c.name, c.content)
		}
	}

	// 同样的路径，来自文件事件时必须照常命中——放行的是来源，不是判据本身。
	if _, hit := d.Scan(context.Background(), IndicatorEvent{
		HostID: "h1", Source: SourceFile, Content: "/etc/cron.hourly/0anacron", ExePath: "/bin/bash",
	}); !hit {
		t.Error("文件事件写入 cron 目录仍应命中，否则等于把检测能力一起关掉")
	}
}

// 提到 ld.so.preload 不等于往里写。日常检查和排查时最常做的就是看这个文件在不在、里面有什么，
// 这些都不该报成动态链接劫持。
func TestRootkitDetector_PreloadReadIsNotHijack(t *testing.T) {
	d := NewRootkitDetector()
	ctx := context.Background()
	scan := func(source, content string) bool {
		_, hit := d.Scan(ctx, IndicatorEvent{HostID: "h1", Source: source, Content: content, ExePath: "/usr/bin/bash"})
		return hit
	}

	for _, cmd := range []string{
		"sudo -n test -f /etc/ld.so.preload",
		"test -f /etc/ld.so.preload",
		"cat /etc/ld.so.preload",
		"ls -la /etc/ld.so.preload",
		"stat /etc/ld.so.preload",
		"grep -c . /etc/ld.so.preload",
		"sha256sum /etc/ld.so.preload",
		"cp /etc/ld.so.preload /tmp/backup",
		"bash -c echo PRELOAD=$(sudo -n test -f /etc/ld.so.preload && echo yes || echo no)",
	} {
		if scan(SourceProcess, cmd) {
			t.Errorf("只读检查不该命中：%q", cmd)
		}
	}

	for _, cmd := range []string{
		"sh -c echo /tmp/evil.so > /etc/ld.so.preload",
		"bash -c echo /lib/x.so >> /etc/ld.so.preload",
		"tee -a /etc/ld.so.preload",
		"cp /tmp/p /etc/ld.so.preload",
		"mv /tmp/p /etc/ld.so.preload",
		"sed -i $a/tmp/evil.so /etc/ld.so.preload",
		"dd if=/tmp/p of=/etc/ld.so.preload",
	} {
		if !scan(SourceProcess, cmd) {
			t.Errorf("写入形态应当命中：%q", cmd)
		}
	}

	// 文件事件是带写意图的打开：路径对上就算，别的路径不算。
	if !scan(SourceFile, "/etc/ld.so.preload") {
		t.Error("ld.so.preload 的文件事件应当命中")
	}
	for _, path := range []string{"/etc/ld.so.preload.bak", "/tmp/etc/ld.so.preload", "/etc/ld.so.conf"} {
		if scan(SourceFile, path) {
			t.Errorf("别的路径不该命中：%q", path)
		}
	}
}

// systemd 的持久化不止 .service：drop-in、timer、socket 都能用，长单元名的后缀还会被采集端截掉。
func TestRootkitDetector_SystemdPersistenceVariants(t *testing.T) {
	d := NewRootkitDetector()
	ctx := context.Background()
	for _, path := range []string{
		"/etc/systemd/system/evil.service",
		"/etc/systemd/system/sshd.service.d/override.conf",
		"/etc/systemd/system/backup.timer",
		"/etc/systemd/system/x.socket",
		"/etc/systemd/system/a-very-long-unit-name-that-gets-cut",
	} {
		if _, hit := d.Scan(ctx, IndicatorEvent{HostID: "h1", Source: SourceFile, Content: path, ExePath: "/usr/bin/bash"}); !hit {
			t.Errorf("应命中：%s", path)
		}
	}
	// 不在真实目录下的同名路径（重建 initramfs 的临时目录）不算。
	if _, hit := d.Scan(ctx, IndicatorEvent{HostID: "h1", Source: SourceFile,
		Content: "/tmp/dracut.x/initramfs/etc/systemd/system/x.service", ExePath: "/usr/bin/bash"}); hit {
		t.Error("临时目录下的路径不该命中")
	}
}
