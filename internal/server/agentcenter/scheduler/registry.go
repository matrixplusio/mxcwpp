package scheduler

import (
	"sort"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

// 后台调度器启动自检。
//
// 这段代码存在的理由：AC 曾有两份初始化文件并存——一份是主程序真正调用的，
// 另一份没有任何调用方。规则同步与 IOC 同步的装配只写在没人调用的那份里，
// 于是这两项能力自平台上线起就没运行过，而没有任何东西会因此报警。
// 后果是全机群 edr_ioc_count 为 0、agent 规则无法热更新。
//
// 静态清单挡不住这类问题：代码里确实"有"NewRuleSyncScheduler 这一行，
// 只是它在死文件里。能挡住的只有运行时事实——谁真的被 go 起来了。
//
// 所以判据是：期望集合在编译期声明，实际集合由每个调度器启动时自己登记，
// 启动完成后比对。差集非空即 ERROR 日志 + 指标非零，可被告警规则捕获。

// ExpectedSchedulers 是 AC 必须启动的后台调度器。
//
// 新增调度器时在此登记；忘记登记不会报警，但忘记 go 起来会——
// 这个方向是刻意的：漏登记只是清单不全，漏启动是能力静默缺失。
var ExpectedSchedulers = []string{
	"plugin_update",
	"agent_update",
	"agent_restart",
	"task_timeout",
	"heartbeat_timeout",
	"push_timeout",
	"ioc_sync",
	"rule_sync",
}

var (
	regMu   sync.Mutex
	started = map[string]bool{}

	missingSchedulers = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxcwpp_ac_scheduler_missing",
		Help: "AC 后台调度器未启动则为 1。非零表示该能力静默缺失。",
	}, []string{"scheduler"})
)

// MarkStarted 由调度器在自身 Start 中调用，登记"我真的跑起来了"。
func MarkStarted(name string) {
	regMu.Lock()
	defer regMu.Unlock()
	started[name] = true
}

// VerifyStarted 比对期望与实际，返回未启动的调度器名。
//
// 在 StartBackgroundServices 末尾调用。调度器的 goroutine 可能尚未执行到
// MarkStarted，故调用方应先给一个短暂的宽限期，否则会误报。
func VerifyStarted(logger *zap.Logger) []string {
	regMu.Lock()
	actual := make(map[string]bool, len(started))
	for k, v := range started {
		actual[k] = v
	}
	regMu.Unlock()

	var missing []string
	for _, name := range ExpectedSchedulers {
		if actual[name] {
			missingSchedulers.WithLabelValues(name).Set(0)
			continue
		}
		missing = append(missing, name)
		missingSchedulers.WithLabelValues(name).Set(1)
	}
	sort.Strings(missing)

	if len(missing) > 0 {
		logger.Error("后台调度器未启动——对应能力静默缺失，不会有其它报错",
			zap.Strings("missing", missing),
			zap.Int("expected", len(ExpectedSchedulers)),
			zap.Int("started", len(actual)))
	} else {
		logger.Info("后台调度器自检通过",
			zap.Int("count", len(ExpectedSchedulers)))
	}
	return missing
}

// StartedSchedulers 返回已登记启动的调度器名，供测试与诊断使用。
func StartedSchedulers() []string {
	regMu.Lock()
	defer regMu.Unlock()
	out := make([]string, 0, len(started))
	for k := range started {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// resetRegistryForTest 清空登记状态，仅供测试使用。
func resetRegistryForTest() {
	regMu.Lock()
	defer regMu.Unlock()
	started = map[string]bool{}
}
