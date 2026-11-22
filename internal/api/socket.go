package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// maxSocketPath is the longest Unix socket path that binds everywhere we run
// (sun_path is 104 bytes on macOS and the BSDs, 108 on Linux, NUL included).
const maxSocketPath = 103

// ErrSocketInUse means something already answers on the socket path.
var ErrSocketInUse = errors.New("api: socket is in use by another process")

// listen opens the API socket at path, readable and writable only by us.
//
// A socket file left by a crash is removed first. The data directory's lock
// already keeps out a second daemon on the same directory; the dial check
// also catches a daemon on another directory pointed at the same socket.
//
// TODO(windows): Go's AF_UNIX works on Windows 10 and later, but mode bits
// don't protect it there. Serve a named pipe with an owner-only ACL (or
// loopback TCP with a token file) instead.
func listen(path string) (net.Listener, error) {
	if len(path) > maxSocketPath {
		return nil, fmt.Errorf("api: socket path %q is %d bytes, over the %d-byte limit for Unix sockets; use a shorter data dir or --socket",
			path, len(path), maxSocketPath)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 && runtime.GOOS != "windows" {
			return nil, fmt.Errorf("api: %s exists and is not a socket", path)
		}
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, fmt.Errorf("%w: %s", ErrSocketInUse, path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("api: removing stale socket: %w", err)
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("api: %w", err)
	}
	// The socket is created with the umask's mode; tighten it at once. The
	// data directory is 0700, so nobody else can reach it in between.
	if err := os.Chmod(path, 0o600); err != nil && runtime.GOOS != "windows" {
		l.Close()
		return nil, fmt.Errorf("api: %w", err)
	}
	return l, nil
}

// Dial connects to a daemon's API socket. The connection is lazy: errors
// show up on the first call.
func Dial(socketPath string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	dialer := func(ctx context.Context, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socketPath)
	}
	opts = append([]grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()), // a 0600 local socket; see api.proto
		grpc.WithContextDialer(dialer),
	}, opts...)
	return grpc.NewClient("passthrough:///openaimd", opts...)
}
