package celengine

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	// processRetainDuration 进程退出后保留时间（用于延迟事件关联）
	processRetainDuration = 2 * time.Hour

	// processTreeCleanupInterval 清理过期进程的间隔
	processTreeCleanupInterval = 10 * time.Minute

	// maxAncestorDepth ancestor_has 查询最大回溯深度
	maxAncestorDepth = 32

	// processIdleTTL 未见退出、且这么久没有活跃的节点，清理时视为已退出。
	//
	// 只靠退出事件淘汰是不够的：退出事件会丢（Agent 侧聚合、网络、重启），
	// 丢一条就漏一个节点，树只增不减，最终把 engine 的内存吃满。
	// 「活跃」指自己被创建或派生了子进程——还在干活的 shell、守护进程会被持续刷新，
	// 祖先链因此不受影响；被淘汰的只是长时间没有动静的节点。
	processIdleTTL = 6 * time.Hour

	// processTreeMaxNodesPerHost 单台主机的节点上限，超出时按最久未活跃淘汰。
	// 正常主机远低于此值；它挡的是异常主机（fork 风暴、PID 高频复用）把整棵树撑爆。
	processTreeMaxNodesPerHost = 50000
)

// procTreeNow 可在测试中替换。
var procTreeNow = time.Now

// ProcessNode 进程树节点
type ProcessNode struct {
	PID       string
	PPID      string
	Exe       string
	Cmdline   string
	UID       string
	StartTime time.Time
	ExitTime  *time.Time // nil = still running

	lastSeen time.Time // 创建或派生子进程时刷新，用于兜底淘汰
	parent   *ProcessNode
	children []*ProcessNode
}

// ProcessTree 按主机维护的进程树
// 键: hostID → pid → ProcessNode
type ProcessTree struct {
	mu     sync.RWMutex
	hosts  map[string]map[string]*ProcessNode // hostID → pid → node
	logger *zap.Logger
}

// NewProcessTree 创建进程树
func NewProcessTree(logger *zap.Logger) *ProcessTree {
	return &ProcessTree{
		hosts:  make(map[string]map[string]*ProcessNode),
		logger: logger,
	}
}

// HandleExec 处理 process_exec 事件，将新进程加入树
func (t *ProcessTree) HandleExec(hostID string, fields map[string]string) {
	pid := fields["pid"]
	ppid := fields["ppid"]
	if pid == "" {
		return
	}

	now := procTreeNow()
	node := &ProcessNode{
		PID:       pid,
		PPID:      ppid,
		Exe:       fields["exe"],
		Cmdline:   fields["cmdline"],
		UID:       fields["uid"],
		StartTime: now,
		lastSeen:  now,
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	hostTree := t.hosts[hostID]
	if hostTree == nil {
		hostTree = make(map[string]*ProcessNode)
		t.hosts[hostID] = hostTree
	}

	// PID 复用：旧进程的退出事件没到，新进程就占了同一个 PID。
	// 只覆盖 map 的话，旧节点仍挂在父节点的 children 里，永远回收不掉。
	if old, ok := hostTree[pid]; ok {
		unlinkFromParent(old)
	}

	// Link to parent if exists.
	if ppid != "" {
		if parent, ok := hostTree[ppid]; ok {
			node.parent = parent
			parent.children = append(parent.children, node)
			parent.lastSeen = now
		}
	}

	hostTree[pid] = node
}

// HandleExit 处理 process_exit 事件，标记进程退出时间
func (t *ProcessTree) HandleExit(hostID string, fields map[string]string) {
	pid := fields["pid"]
	if pid == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	hostTree := t.hosts[hostID]
	if hostTree == nil {
		return
	}

	if node, ok := hostTree[pid]; ok {
		now := procTreeNow()
		node.ExitTime = &now
	}
}

// Lookup 返回进程号对应的程序路径与命令行。已退出的进程在被清理前仍可查到：
// 它的文件与网络事件可能比退出事件晚到。
func (t *ProcessTree) Lookup(hostID, pid string) (procInfo, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	node, ok := t.hosts[hostID][pid]
	if !ok {
		return procInfo{}, false
	}
	return procInfo{exe: node.Exe, cmdline: node.Cmdline}, true
}

// AncestorHas 检查指定主机上的进程祖先链中是否有匹配 exe 的进程
// 用于 CEL 自定义函数 ancestor_has(exe_pattern)
func (t *ProcessTree) AncestorHas(hostID, pid, exePattern string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	hostTree := t.hosts[hostID]
	if hostTree == nil {
		return false
	}

	node, ok := hostTree[pid]
	if !ok {
		return false
	}

	// Walk up the parent chain.
	current := node.parent
	for depth := 0; current != nil && depth < maxAncestorDepth; depth++ {
		if containsPattern(current.Exe, exePattern) {
			return true
		}
		current = current.parent
	}

	return false
}

// GetAncestorChain 返回进程的祖先链 exe 列表（从近到远）
func (t *ProcessTree) GetAncestorChain(hostID, pid string) []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	hostTree := t.hosts[hostID]
	if hostTree == nil {
		return nil
	}

	node, ok := hostTree[pid]
	if !ok {
		return nil
	}

	var chain []string
	current := node.parent
	for depth := 0; current != nil && depth < maxAncestorDepth; depth++ {
		chain = append(chain, current.Exe)
		current = current.parent
	}

	return chain
}

// CleanupResult 一轮清理按原因分别计数。
type CleanupResult struct {
	Exited int // 已退出且超过保留时间
	Idle   int // 未见退出，但超过 processIdleTTL 没有活跃
	Capped int // 单台主机超过节点上限，按最久未活跃淘汰
}

// Total 本轮清理的节点总数。
func (r CleanupResult) Total() int { return r.Exited + r.Idle + r.Capped }

// Cleanup 清理过期进程节点。
func (t *ProcessTree) Cleanup() CleanupResult {
	now := procTreeNow()
	exitCutoff := now.Add(-processRetainDuration)
	idleCutoff := now.Add(-processIdleTTL)

	t.mu.Lock()
	defer t.mu.Unlock()

	var res CleanupResult
	for hostID, hostTree := range t.hosts {
		for pid, node := range hostTree {
			switch {
			case node.ExitTime != nil && node.ExitTime.Before(exitCutoff):
				removeNode(hostTree, pid, node)
				res.Exited++
			case node.ExitTime == nil && node.lastSeen.Before(idleCutoff):
				removeNode(hostTree, pid, node)
				res.Idle++
			}
		}

		if excess := len(hostTree) - processTreeMaxNodesPerHost; excess > 0 {
			nodes := make([]*ProcessNode, 0, len(hostTree))
			for _, n := range hostTree {
				nodes = append(nodes, n)
			}
			sort.Slice(nodes, func(i, j int) bool { return nodes[i].lastSeen.Before(nodes[j].lastSeen) })
			for _, n := range nodes[:excess] {
				removeNode(hostTree, n.PID, n)
				res.Capped++
			}
		}

		// Remove empty host trees.
		if len(hostTree) == 0 {
			delete(t.hosts, hostID)
		}
	}

	if res.Total() > 0 {
		t.logger.Debug("进程树清理", zap.Int("removed", res.Total()))
	}

	return res
}

// removeNode 从树中摘除节点，子节点重挂到祖父节点。
func removeNode(hostTree map[string]*ProcessNode, pid string, node *ProcessNode) {
	grandparent := node.parent // unlinkFromParent 会清空 node.parent，先记下
	unlinkFromParent(node)
	for _, child := range node.children {
		child.parent = grandparent
		if grandparent != nil {
			grandparent.children = append(grandparent.children, child)
		}
	}
	node.children = nil
	if hostTree[pid] == node {
		delete(hostTree, pid)
	}
}

// unlinkFromParent 把节点从父节点的 children 里摘掉。
func unlinkFromParent(node *ProcessNode) {
	if node.parent == nil {
		return
	}
	siblings := node.parent.children
	for i, c := range siblings {
		if c == node {
			node.parent.children = append(siblings[:i], siblings[i+1:]...)
			break
		}
	}
	node.parent = nil
}

// Stats 返回进程树统计
func (t *ProcessTree) Stats() (hosts int, totalNodes int) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	hosts = len(t.hosts)
	for _, hostTree := range t.hosts {
		totalNodes += len(hostTree)
	}
	return
}

// containsPattern 简单模式匹配（包含检查）
func containsPattern(exe, pattern string) bool {
	if pattern == "" {
		return false
	}
	return exe == pattern || len(exe) > 0 && len(pattern) > 0 && contains(exe, pattern)
}

// contains is a simple substring check (avoid importing strings for this one use).
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// LineageRoot 是一个进程所属的「血缘根」：同一次登录会话、同一个服务、同一个定时任务、
// 同一个容器入口派生出来的进程共用一个根。风险累积以它为单位，避免把同一台机器上互不相关的
// 活动（运维登录、业务服务、定时任务）凑成一条攻击链。
type LineageRoot struct {
	// Key 在主机内唯一：根进程号加上首次看到它的时间（进程号会复用）。
	Key     string
	PID     string
	Exe     string
	Cmdline string
}

// lineageBoundary 父进程是这些程序时，子进程就是一段独立活动的起点。
var lineageBoundary = map[string]bool{
	"sshd": true, "sshd-session": true, "systemd": true, "init": true,
	"cron": true, "crond": true, "atd": true,
	"containerd-shim": true, "containerd-shim-runc-v2": true, "conmon": true, "runc": true,
}

// LineageRoot 沿父链往上找血缘根：遇到登录会话、服务管理器、定时任务、容器入口这类边界就停，
// 父链断了（祖先在 agent 启动前就已存在、没有它的执行事件）就取已知的最上层。
// 进程不在树里时返回 false，调用方退到主机级。
func (t *ProcessTree) LineageRoot(hostID, pid string) (LineageRoot, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	node := t.hosts[hostID][pid]
	if node == nil {
		return LineageRoot{}, false
	}
	for depth := 0; depth < maxAncestorDepth && node.parent != nil; depth++ {
		p := node.parent
		if p.PID == "1" || isLineageBoundary(p.Exe) {
			break
		}
		node = p
	}
	return LineageRoot{
		Key:     node.PID + "@" + strconv.FormatInt(node.StartTime.UnixNano(), 36),
		PID:     node.PID,
		Exe:     node.Exe,
		Cmdline: node.Cmdline,
	}, true
}

// systemBinDirs 边界程序必须在这些目录下。只看程序名的话，把 bash 拷成 /tmp/cron 再用它派生
// 每一步，每条命令都会自成一个根；放进系统目录要先有 root 写权限。
var systemBinDirs = []string{"/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/", "/usr/lib/systemd/", "/lib/systemd/", "/usr/libexec/"}

func isLineageBoundary(exe string) bool {
	if !lineageBoundary[exeBase(exe)] {
		return false
	}
	for _, d := range systemBinDirs {
		if strings.HasPrefix(exe, d) && !strings.Contains(exe[len(d):], "/") {
			return true
		}
	}
	return false
}

func exeBase(exe string) string {
	if i := strings.LastIndexByte(exe, '/'); i >= 0 {
		exe = exe[i+1:]
	}
	return exe
}

// LineageRoot 返回进程的血缘根（见 ProcessTree.LineageRoot）。
func (e *Engine) LineageRoot(hostID, pid string) (LineageRoot, bool) {
	if e == nil || e.procTree == nil || pid == "" {
		return LineageRoot{}, false
	}
	return e.procTree.LineageRoot(hostID, pid)
}
