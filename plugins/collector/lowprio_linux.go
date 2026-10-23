//go:build linux

package main

import (
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

const (
	ioprioWhoProcess = 1
	ioprioClassIdle  = 3
	ioprioClassShift = 13
)

// lowerPriority 把 collector 降到最低 CPU 与 IO 优先级：资产盘点不赶时间，绝不能和业务进程抢资源。
//
// nice 与 IO 优先级在 Linux 上按线程生效，启动时 Go 运行时已经建好的线程不会继承，
// 所以逐个设置 /proc/self/task 下的线程；之后新建的线程从创建它的线程继承。设两遍覆盖遍历期间新建的线程。
func lowerPriority() error {
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
			if err := unix.Setpriority(unix.PRIO_PROCESS, tid, 19); err != nil && firstErr == nil {
				firstErr = err
			}
			if _, _, errno := unix.Syscall(unix.SYS_IOPRIO_SET, ioprioWhoProcess, uintptr(tid), ioprioClassIdle<<ioprioClassShift); errno != 0 && firstErr == nil {
				firstErr = errno
			}
		}
	}
	return firstErr
}
