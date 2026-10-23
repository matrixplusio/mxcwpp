//go:build linux

package auth

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// setChildAttrs 让子进程在插件退出时一起结束。
// agent 强杀插件时不会走到任何清理代码，不这样做会留下没人管的 journalctl。
func setChildAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

const (
	ioprioWhoProcess    = 1
	ioprioClassBE       = 2
	ioprioClassShift    = 13
	ioprioLowestBELevel = 7

	lowNice = 10
)

// 插件、journalctl 与 EDR 采集同在 agent 的 cgroup 里，共用一份 CPU 配额。降低这两个的优先级，
// 是为了配额吃紧时让出给 EDR，而不是和它平分。
//
// IO 用 best-effort 的最低档而不是 idle：idle 在磁盘持续繁忙时可以一直排不上，
// 认证事件就会无限期地晚到；最低档只是排在后面，不会饿死。

// LowerSelfPriority 降低插件自身所有线程的 CPU 与 IO 优先级。
//
// nice 与 IO 优先级在 Linux 上按线程生效，已经建好的线程不会跟着变，
// 所以逐个设置 /proc/self/task 下的线程；之后新建的线程从创建它的线程继承。设两遍覆盖遍历期间新建的线程。
func LowerSelfPriority() error {
	var firstErr error
	for pass := 0; pass < 2; pass++ {
		entries, err := os.ReadDir("/proc/self/task")
		if err != nil {
			return err
		}
		for _, e := range entries {
			tid, err := strconv.Atoi(e.Name())
			if err != nil {
				continue
			}
			if err := lowerTaskPriority(tid); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// lowerChildPriority 降低 journalctl 的优先级。它是单线程程序，设主线程即可。
func lowerChildPriority(pid int) error {
	return lowerTaskPriority(pid)
}

func lowerTaskPriority(tid int) error {
	err := unix.Setpriority(unix.PRIO_PROCESS, tid, lowNice)
	if _, _, errno := unix.Syscall(unix.SYS_IOPRIO_SET, ioprioWhoProcess, uintptr(tid),
		ioprioClassBE<<ioprioClassShift|ioprioLowestBELevel); errno != 0 && err == nil {
		err = errno
	}
	return err
}
