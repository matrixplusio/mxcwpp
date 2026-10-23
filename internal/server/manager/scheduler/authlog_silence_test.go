package scheduler

import (
	"testing"
	"time"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func authlogHost(id string, status model.HostStatus, hb, start time.Time) model.Host {
	h := model.Host{HostID: id, Hostname: id, Status: status}
	t := model.ToLocalTime(hb)
	h.LastHeartbeat = &t
	if !start.IsZero() {
		s := model.ToLocalTime(start)
		h.AgentStartTime = &s
	}
	return h
}

func TestDecideAuthlogSilence(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.Local)
	long := now.Add(-48 * time.Hour)
	last := map[string]time.Time{
		"ok":        now.Add(-3 * time.Minute),
		"silent":    now.Add(-30 * time.Minute),
		"offline":   now.Add(-30 * time.Minute),
		"booting":   now.Add(-30 * time.Minute),
		"recovered": now.Add(-1 * time.Minute),
		"went-off":  now.Add(-40 * time.Minute),
		"already":   now.Add(-40 * time.Minute),
	}
	hosts := []model.Host{
		authlogHost("ok", model.HostStatusOnline, now, long),
		authlogHost("silent", model.HostStatusOnline, now, long),
		authlogHost("offline", model.HostStatusOffline, now.Add(-time.Hour), long),
		authlogHost("booting", model.HostStatusOnline, now, now.Add(-5*time.Minute)),
		authlogHost("recovered", model.HostStatusOnline, now, long),
		authlogHost("went-off", model.HostStatusOffline, now.Add(-time.Hour), long),
		authlogHost("already", model.HostStatusOnline, now, long),
	}
	active := map[string]bool{"recovered": true, "went-off": true, "already": true}

	d := decideAuthlogSilence(last, hosts, active, now.Add(-time.Minute), now)
	if d.pipelineStale {
		t.Fatal("还有主机的心跳是新的，不是管道问题")
	}
	if len(d.open) != 1 || d.open[0].HostID != "silent" {
		t.Fatalf("只该为在线、心跳停了、不在启动宽限期、尚无告警的主机开告警: %+v", d.open)
	}
	if len(d.resolve) != 2 || d.resolve["recovered"] == "" || d.resolve["went-off"] == "" {
		t.Fatalf("心跳恢复与转为离线的应恢复: %v", d.resolve)
	}
}

// 落库管道停了的时候，所有主机的心跳同时变旧，不能逐台告警。
func TestDecideAuthlogSilencePipelineStale(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.Local)
	last := map[string]time.Time{"a": now.Add(-20 * time.Minute), "b": now.Add(-25 * time.Minute)}
	hosts := []model.Host{
		authlogHost("a", model.HostStatusOnline, now, now.Add(-48*time.Hour)),
		authlogHost("b", model.HostStatusOnline, now, now.Add(-48*time.Hour)),
	}
	d := decideAuthlogSilence(last, hosts, nil, now.Add(-30*time.Minute), now)
	if !d.pipelineStale || len(d.open) != 0 {
		t.Fatalf("got %+v", d)
	}
	// 内核事件还在落库、只有心跳全停（插件全体崩溃、或只有一两台装了插件）：必须逐台报。
	d = decideAuthlogSilence(last, hosts, nil, now.Add(-time.Minute), now)
	if d.pipelineStale || len(d.open) != 2 {
		t.Fatalf("插件全体停了不是管道问题: %+v", d)
	}
}

// 主机把时钟拨快、报一个未来的启动时间，不能因此一直处在启动宽限期里。
func TestDecideAuthlogSilenceIgnoresFutureStartTime(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.Local)
	last := map[string]time.Time{"h": now.Add(-3 * time.Hour)}
	hosts := []model.Host{authlogHost("h", model.HostStatusOnline, now, now.Add(24*time.Hour))}
	d := decideAuthlogSilence(last, hosts, nil, now, now)
	if len(d.open) != 1 {
		t.Fatalf("未来的启动时间不该给宽限: %+v", d)
	}
}
