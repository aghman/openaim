package daemon

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ErrLocked is returned when another daemon holds the data directory.
var ErrLocked = errors.New("daemon: data dir is in use by another openaimd")

// Lock is an exclusive hold on a data directory. It is an OS file lock on the
// pidfile, so the kernel drops it when the process dies: a pidfile left by a
// crash is stale by construction and is simply taken over.
type Lock struct {
	f *os.File
}

// AcquireLock takes the data directory's lock or fails with ErrLocked. It
// never waits.
func AcquireLock(path string) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("daemon: lock: %w", err)
	}
	if err := lockFile(f); err != nil {
		f.Close()
		if errors.Is(err, errWouldBlock) {
			if pid := readPid(path); pid != 0 {
				return nil, fmt.Errorf("%w (pid %d)", ErrLocked, pid)
			}
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("daemon: lock: %w", err)
	}
	// Record our pid for humans and tools. The lock, not the contents, is
	// what keeps a second daemon out.
	if err := f.Truncate(0); err == nil {
		f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
		f.Sync()
	}
	return &Lock{f: f}, nil
}

// Release clears the pidfile and drops the lock. The file itself stays:
// deleting a lock file while others may have it open lets two processes
// each lock a different inode.
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	l.f.Truncate(0)
	err := unlockFile(l.f)
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	l.f = nil
	return err
}

func readPid(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return pid
}
