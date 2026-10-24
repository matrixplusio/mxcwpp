//go:build linux

package edr

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func immutableFlags(t *testing.T, path string) uint32 {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer unix.Close(fd)
	flags, err := unix.IoctlGetUint32(fd, unix.FS_IOC_GETFLAGS)
	if err != nil {
		t.Skipf("filesystem does not support FS_IOC_GETFLAGS: %v", err)
	}
	return flags
}

// A symlink planted in a protected dir must not redirect the lock to its target.
func TestSetImmutableFlagRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := setImmutableFlag(link, true); !errors.Is(err, unix.ELOOP) {
		t.Fatalf("symlink: want ELOOP, got %v", err)
	}
	if immutableFlags(t, target)&fsImmutableFL != 0 {
		t.Fatal("symlink target was locked")
	}
}

// A hard link to a file outside the protected dir must not lock that inode.
func TestSetImmutableFlagRejectsHardLink(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, "orig")
	if err := os.WriteFile(orig, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(orig, filepath.Join(dir, "hard")); err != nil {
		t.Skipf("link: %v", err)
	}
	if err := setImmutableFlag(filepath.Join(dir, "hard"), true); !errors.Is(err, unix.EMLINK) {
		t.Fatalf("hard link: want EMLINK, got %v", err)
	}
}

// A FIFO must be rejected without blocking on open.
func TestSetImmutableFlagRejectsFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- setImmutableFlag(fifo, true) }()
	select {
	case err := <-done:
		if !errors.Is(err, unix.EINVAL) {
			t.Fatalf("fifo: want EINVAL, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("open blocked on FIFO")
	}
}

// With CAP_LINUX_IMMUTABLE the flag is set and cleared; without it the call
// fails with EPERM instead of silently reporting success. CI runs unprivileged,
// so the round trip itself is only exercised when run as root.
func TestSetImmutableFlagRoundTrip(t *testing.T) {
	f := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	immutableFlags(t, f) // skips on filesystems without attribute support

	err := setImmutableFlag(f, true)
	if errors.Is(err, unix.EPERM) {
		if immutableFlags(t, f)&fsImmutableFL != 0 {
			t.Fatal("EPERM returned but flag was set")
		}
		t.Skip("no CAP_LINUX_IMMUTABLE; round trip needs root")
	}
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	t.Cleanup(func() { _ = setImmutableFlag(f, false) })

	if immutableFlags(t, f)&fsImmutableFL == 0 {
		t.Fatal("immutable flag not set")
	}
	if err := os.WriteFile(f, []byte("y"), 0o600); err == nil {
		t.Fatal("write succeeded on immutable file")
	}
	if err := setImmutableFlag(f, false); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if immutableFlags(t, f)&fsImmutableFL != 0 {
		t.Fatal("immutable flag not cleared")
	}
}
