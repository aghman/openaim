// Package api serves the openaimd local client API (proto/openaim/api/v1)
// over gRPC on a Unix socket, and runs the daemon's lifecycle around a
// daemon.Node: open, listen, serve, and shut down cleanly on a signal or a
// Shutdown call.
package api

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"

	pb "github.com/aghman/openaim/internal/apipb"
	"github.com/aghman/openaim/internal/daemon"
)

// Config configures a daemon.
type Config struct {
	daemon.Config
	// SocketPath overrides the API socket (default: in the data dir).
	SocketPath string
	// GracePeriod bounds how long shutdown waits for in-flight calls
	// before cutting them off; zero means 5 s.
	GracePeriod time.Duration
}

// Daemon is a running openaimd: a node serving the API.
type Daemon struct {
	node   *daemon.Node
	grpc   *grpc.Server
	lis    net.Listener
	socket string
	log    *slog.Logger
	grace  time.Duration

	stopping chan struct{} // closed when shutdown starts
	done     chan struct{} // closed when shutdown has finished
	stopOnce sync.Once
	reqOnce  sync.Once
	stopReq  chan struct{} // closed by a Shutdown call
	serveErr error
}

// Start opens the node and starts serving the API. The daemon runs until
// Stop, a Shutdown call, or (with Run) the context ends.
func Start(ctx context.Context, cfg Config) (*Daemon, error) {
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
		cfg.Logger = log
	}
	n, err := daemon.Open(ctx, cfg.Config)
	if err != nil {
		return nil, err
	}
	sock := cfg.SocketPath
	if sock == "" {
		sock = n.Paths().Socket
	}
	lis, err := listen(sock)
	if err != nil {
		n.Close()
		return nil, err
	}
	d := &Daemon{
		node: n, lis: lis, socket: sock, log: log, grace: cfg.GracePeriod,
		stopping: make(chan struct{}), done: make(chan struct{}), stopReq: make(chan struct{}),
	}
	if d.grace == 0 {
		d.grace = 5 * time.Second
	}
	d.grpc = grpc.NewServer(grpc.ChainUnaryInterceptor(logUnary(log)))
	pb.RegisterDaemonServer(d.grpc, &server{n: n, d: d, log: log})

	served := make(chan error, 1)
	go func() { served <- d.grpc.Serve(lis) }()
	go func() {
		select {
		case <-d.stopReq:
		case err := <-served:
			// Serve only returns early if the listener broke.
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				d.serveErr = err
				log.Error("api server stopped", "err", err)
			}
		}
		d.shutdown()
	}()
	log.Info("openaimd serving", "socket", sock, "version", daemon.BuildVersion(), "key_id", n.Identity().KeyID())
	return d, nil
}

// Run starts a daemon and serves until ctx ends or a client calls Shutdown.
func Run(ctx context.Context, cfg Config) error {
	d, err := Start(ctx, cfg)
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		d.log.Info("signal received; shutting down")
		d.Stop()
	case <-d.Done():
	}
	return d.Err()
}

// Node is the daemon's core, for in-process use (tests, an embedded TUI).
func (d *Daemon) Node() *daemon.Node { return d.node }

// SocketPath is where the API is served.
func (d *Daemon) SocketPath() string { return d.socket }

// Done is closed once the daemon has fully stopped.
func (d *Daemon) Done() <-chan struct{} { return d.done }

// Err is why the daemon stopped on its own, after Done; nil for a requested
// stop.
func (d *Daemon) Err() error {
	<-d.done
	return d.serveErr
}

// Stop shuts the daemon down and waits for it. It is safe to call more than
// once and from several goroutines.
func (d *Daemon) Stop() {
	d.requestStop()
	<-d.done
}

func (d *Daemon) requestStop() { d.reqOnce.Do(func() { close(d.stopReq) }) }

// shutdown ends event streams, lets in-flight calls finish (up to the grace
// period), removes the socket and closes the node, which releases the data
// directory lock.
func (d *Daemon) shutdown() {
	d.stopOnce.Do(func() {
		defer close(d.done)
		close(d.stopping) // event streams return
		graceful := make(chan struct{})
		go func() { d.grpc.GracefulStop(); close(graceful) }()
		select {
		case <-graceful:
		case <-time.After(d.grace):
			d.log.Warn("calls still running after grace period; cutting them off")
			d.grpc.Stop()
			<-graceful
		}
		// The listener unlinks the socket on close; make sure of it.
		if err := os.Remove(d.socket); err != nil && !errors.Is(err, os.ErrNotExist) {
			d.log.Warn("removing socket", "err", err)
		}
		if err := d.node.Close(); err != nil {
			d.log.Error("closing node", "err", err)
		}
		d.log.Info("openaimd stopped")
	})
}
