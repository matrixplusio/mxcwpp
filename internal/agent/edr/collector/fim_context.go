//go:build linux

package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"

	"github.com/matrixplusio/mxcwpp/internal/agent/edr/event"
)

// parseUID 将数字字符串解析为 uid,失败返回 0。
func parseUID(s string) uint32 {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(v)
}

// FIM 事件上下文增强:给文件事件补"谁改的/谁登录的/改了什么"三类溯源字段。
// 采集在 agent 侧(符合 agent=采集职责),映射/关联仍由 engine 做重活。

// uidNameCache 缓存 uid→username(/etc/passwd 极少变),避免每事件 LookupId 开销。
var uidNameCache sync.Map // map[uint32]string

// usernameFromUID 解析 uid 为用户名,失败返回空串(仅补充,不影响主流程)。
func usernameFromUID(uid uint32) string {
	if v, ok := uidNameCache.Load(uid); ok {
		return v.(string)
	}
	name := ""
	if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		name = u.Username
	}
	uidNameCache.Store(uid, name)
	return name
}

// readLoginUID 读取 /proc/<pid>/loginuid(内核审计 login uid,溯源到发起登录的真实用户)。
// 值为 4294967295(-1)表示无登录会话(如内核线程/系统服务),视为空。
func readLoginUID(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/loginuid", pid))
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(data))
	if s == "" || s == "4294967295" {
		return ""
	}
	return s
}

// readProcUIDPPID 从 /proc/<pid>/status 解析真实 uid 与 ppid(fanotify 事件只带 pid,需补)。
// ok=false 表示进程已退出/读不到 —— 此时不可把 uid 当 0(root),调用方应跳过。
func readProcUIDPPID(pid int) (uid uint32, ppid int, ok bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				uid = parseUID(f[1]) // 第一列是 real uid
			}
		} else if strings.HasPrefix(line, "PPid:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				if v, e := strconv.Atoi(f[1]); e == nil {
					ppid = v
				}
			}
		}
	}
	return uid, ppid, true
}

// enrichFileEventContext 给文件事件补 FIM 溯源上下文(username/parent_exe/login_uid/敏感文件哈希),
// eBPF 与 fanotify 两条采集路径共用。uid/ppid 为 0 (fanotify 只带 pid) 时从 /proc/<pid> 兜底;
// 兜底读失败(短命进程已退出)则不硬设 root,只补能拿到的字段。
func enrichFileEventContext(evt *event.Event, pid int, uid uint32, ppid int, filePath string) {
	haveActor := true
	if uid == 0 && ppid == 0 && pid > 0 {
		var ok bool
		uid, ppid, ok = readProcUIDPPID(pid)
		haveActor = ok
	}
	if haveActor {
		if name := usernameFromUID(uid); name != "" {
			evt.SetField("username", name)
		}
		if ppid > 0 {
			if pexe := readProcExe(ppid); pexe != "" {
				evt.SetField("parent_exe", pexe)
			}
		}
	}
	if lu := readLoginUID(pid); lu != "" {
		evt.SetField("login_uid", lu)
		if lname := usernameFromUID(parseUID(lu)); lname != "" {
			evt.SetField("login_user", lname)
		}
	}
	if hash, size := sensitiveFileHash(filePath); hash != "" {
		evt.SetField("content_hash", hash)
		evt.SetField("file_size", fmt.Sprintf("%d", size))
	}
}

// sensitiveFilePrefixes 敏感文件路径前缀:仅对这些路径做内容哈希(防篡改取证),
// 避免对全量文件读内容(性能 + 隐私)。
var sensitiveFilePrefixes = []string{
	"/etc/ssh/",
	"/etc/sudoers",
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/pam.d/",
	"/etc/crontab",
	"/etc/cron.d/",
	"/root/.ssh/",
}

const sensitiveHashMaxSize = 1 << 20 // 1MB 上限,敏感配置文件通常几 KB

// isSensitiveFile 判断路径是否属于敏感文件(廉价前缀匹配,先于读文件)。
func isSensitiveFile(path string) bool {
	for _, p := range sensitiveFilePrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// sensitiveFileHash 计算敏感文件当前内容的 SHA256 + 大小,用于篡改取证。
// 非敏感文件、超限、读失败均返回空(不阻塞事件)。存在读取与事件间的竞态,取证证据非强一致。
func sensitiveFileHash(path string) (hash string, size int64) {
	if !isSensitiveFile(path) {
		return "", 0
	}
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > sensitiveHashMaxSize {
		return "", 0
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), int64(len(data))
}
