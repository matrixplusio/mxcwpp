package celengine

import (
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"
)

// fakeClock 让测试控制进程树看到的「现在」。
func fakeClock(t *testing.T) *time.Time {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	prev := procTreeNow
	procTreeNow = func() time.Time { return now }
	t.Cleanup(func() { procTreeNow = prev })
	return &now
}

func exec(tree *ProcessTree, host, pid, ppid, exe string) {
	tree.HandleExec(host, map[string]string{"pid": pid, "ppid": ppid, "exe": exe})
}

func nodeCount(tree *ProcessTree) int {
	_, n := tree.Stats()
	return n
}

// 退出事件丢了的节点也必须能回收——这正是此前泄漏的成因：
// 只删「已退出」的节点，退出事件一丢，节点就永远留在树上。
func TestCleanupRemovesIdleNodesWithoutExitEvent(t *testing.T) {
	now := fakeClock(t)
	tree := NewProcessTree(zap.NewNop())

	exec(tree, "h1", "100", "", "/usr/bin/sleep")
	*now = now.Add(processIdleTTL + time.Minute)

	res := tree.Cleanup()
	if res.Idle != 1 || nodeCount(tree) != 0 {
		t.Fatalf("未见退出且长期不活跃的节点应被回收: %+v, 剩余 %d", res, nodeCount(tree))
	}
}

// 仍在派生子进程的祖先不能被淘汰，否则 ancestor_has 会对正在发生的事情失明。
func TestCleanupKeepsActiveAncestors(t *testing.T) {
	now := fakeClock(t)
	tree := NewProcessTree(zap.NewNop())

	exec(tree, "h1", "1", "", "/usr/sbin/sshd")
	exec(tree, "h1", "2", "1", "/bin/bash")
	for i := 0; i < 10; i++ {
		*now = now.Add(time.Hour)
		exec(tree, "h1", fmt.Sprintf("%d", 100+i), "2", "/usr/bin/ls")
	}

	tree.Cleanup()
	if !tree.AncestorHas("h1", "109", "bash") {
		t.Fatal("bash 每小时都在派生子进程，不应被当成不活跃淘汰")
	}
	// sshd 自创建 bash 之后再没派生过子进程，已超过 TTL，应被回收。
	if tree.AncestorHas("h1", "109", "sshd") {
		t.Fatal("sshd 超过 TTL 没有活跃，应被回收")
	}
}

// 已退出节点仍按原有保留期回收，行为不变。
func TestCleanupRemovesExitedNodesAfterRetention(t *testing.T) {
	now := fakeClock(t)
	tree := NewProcessTree(zap.NewNop())

	exec(tree, "h1", "100", "", "/usr/bin/curl")
	tree.HandleExit("h1", map[string]string{"pid": "100"})

	*now = now.Add(processRetainDuration - time.Minute)
	if res := tree.Cleanup(); res.Total() != 0 {
		t.Fatalf("保留期内不应回收: %+v", res)
	}
	*now = now.Add(2 * time.Minute)
	if res := tree.Cleanup(); res.Exited != 1 {
		t.Fatalf("超过保留期应按已退出回收: %+v", res)
	}
}

// 单台主机超过上限时按最久未活跃淘汰，新近的节点保留。
func TestCleanupCapsNodesPerHost(t *testing.T) {
	now := fakeClock(t)
	tree := NewProcessTree(zap.NewNop())

	total := processTreeMaxNodesPerHost + 100
	for i := 0; i < total; i++ {
		*now = now.Add(time.Millisecond)
		exec(tree, "h1", fmt.Sprintf("%d", i), "", "/bin/true")
	}

	res := tree.Cleanup()
	if res.Capped != 100 || nodeCount(tree) != processTreeMaxNodesPerHost {
		t.Fatalf("应淘汰超出的 100 个: %+v, 剩余 %d", res, nodeCount(tree))
	}
	if tree.GetAncestorChain("h1", "0") != nil || tree.hosts["h1"]["0"] != nil {
		t.Fatal("最旧的节点应被淘汰")
	}
	if tree.hosts["h1"][fmt.Sprintf("%d", total-1)] == nil {
		t.Fatal("最新的节点应保留")
	}
}

// PID 复用时旧节点必须从父节点的 children 里摘掉，否则它永远回收不掉。
func TestPIDReuseUnlinksOldNode(t *testing.T) {
	fakeClock(t)
	tree := NewProcessTree(zap.NewNop())

	exec(tree, "h1", "1", "", "/usr/sbin/crond")
	exec(tree, "h1", "50", "1", "/bin/sh")
	exec(tree, "h1", "50", "1", "/usr/bin/python3") // 退出事件丢失，PID 被复用

	parent := tree.hosts["h1"]["1"]
	if len(parent.children) != 1 || parent.children[0].Exe != "/usr/bin/python3" {
		t.Fatalf("父节点应只挂着新进程，实际 %d 个子节点", len(parent.children))
	}
}

// 中间节点被回收后，子节点重挂到祖父节点，祖先链不断。
func TestRemovedNodeReparentsChildren(t *testing.T) {
	now := fakeClock(t)
	tree := NewProcessTree(zap.NewNop())

	exec(tree, "h1", "1", "", "/usr/sbin/sshd")
	exec(tree, "h1", "2", "1", "/bin/bash")
	exec(tree, "h1", "3", "2", "/usr/bin/vim")
	tree.HandleExit("h1", map[string]string{"pid": "2"})

	*now = now.Add(processRetainDuration + time.Minute)
	tree.Cleanup()

	if chain := tree.GetAncestorChain("h1", "3"); len(chain) != 1 || chain[0] != "/usr/sbin/sshd" {
		t.Fatalf("bash 回收后 vim 应挂到 sshd 下，实际祖先链 %v", chain)
	}
}

// 稳态：持续有进程启动、退出事件全部丢失，节点数也不会单调增长。
func TestTreeStaysBoundedWhenExitEventsAreLost(t *testing.T) {
	now := fakeClock(t)
	tree := NewProcessTree(zap.NewNop())

	pid := 0
	var peak int
	for round := 0; round < 72; round++ { // 72 轮 × 10 分钟 = 12 小时
		for i := 0; i < 500; i++ {
			pid++
			exec(tree, "h1", fmt.Sprintf("%d", pid), "", "/bin/true")
		}
		*now = now.Add(processTreeCleanupInterval)
		tree.Cleanup()
		if n := nodeCount(tree); n > peak {
			peak = n
		}
	}
	// 每轮 500 个、6 小时 TTL → 稳态约 36 轮 × 500 = 18000。
	if limit := int(processIdleTTL/processTreeCleanupInterval)*500 + 500; peak > limit {
		t.Fatalf("节点数应在 TTL 窗口内收敛，峰值 %d 超过 %d", peak, limit)
	}
}
