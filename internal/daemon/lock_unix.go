//go:build unix

package daemon

import (
	"os"
	"syscall"
)

var errWouldBlock = syscall.EWOULDBLOCK

// lockFile takes a non-blocking flock. flock locks belong to the open file
// description, so a second open of the same file conflicts even within one
// process (which the tests rely on).
func lockFile(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err != syscall.EINTR {
			return err
		}
	}
}

func unlockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
