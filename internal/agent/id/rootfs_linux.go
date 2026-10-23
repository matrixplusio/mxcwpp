//go:build linux

package id

import (
	"os"
	"path/filepath"
	"syscall"
)

// rootFSUUID 找到挂载在 / 的块设备，再在 /dev/disk/by-uuid 里找指向它的链接。
// 用设备号比对而不是解析 mountinfo 的设备名：overlay、LVM、dm 设备的名字形态各异，设备号是唯一可靠的。
func rootFSUUID() string {
	var root syscall.Stat_t
	if err := syscall.Stat("/", &root); err != nil {
		return ""
	}
	entries, err := os.ReadDir("/dev/disk/by-uuid")
	if err != nil {
		return ""
	}
	for _, e := range entries {
		var st syscall.Stat_t
		if err := syscall.Stat(filepath.Join("/dev/disk/by-uuid", e.Name()), &st); err != nil {
			continue
		}
		if uint64(st.Rdev) == uint64(root.Dev) {
			return e.Name()
		}
	}
	return ""
}
