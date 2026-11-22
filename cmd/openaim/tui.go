package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aghman/openaim/internal/api"
	pb "github.com/aghman/openaim/internal/apipb"
	"github.com/aghman/openaim/internal/daemon"
	"github.com/aghman/openaim/internal/tui"
)

// envPassphrase is openaimd's keystore passphrase variable, used by
// tui --embedded.
const envPassphrase = "OPENAIM_PASSPHRASE"

var cmdTUI = &command{
	name: "tui", synopsis: "[--embedded]", summary: "open the full-screen buddy list and IM windows",
	help: `The terminal client (design §11.2): the buddy list on the left, the IM
window on the right. Press F1 (or ? in the buddy list) for the keys.

It talks to a running openaimd, and reconnects by itself if the daemon
restarts. If none is running, it offers to run one inside the TUI for as
long as the TUI is open (other clients can use it meanwhile); --embedded
does that without asking. The keystore passphrase then comes from
--passphrase-file, else $OPENAIM_PASSPHRASE, else a prompt before the
screen opens. NO_COLOR turns colors off.
`,
	setup: func(fs *flag.FlagSet) runFunc {
		embedded := fs.Bool("embedded", false, "if openaimd isn't running, run it inside the TUI without asking")
		passFile := fs.String("passphrase-file", "", "with an embedded daemon: read the keystore passphrase from this file")
		return func(ctx context.Context, cl *cli, args []string) error {
			if err := nargs(args, 0, 0); err != nil {
				return err
			}
			if cl.g.json {
				return usageErrorf("tui has no --json output")
			}
			return cl.tui(ctx, *embedded, *passFile)
		}
	},
}

func (cl *cli) tui(ctx context.Context, embedded bool, passFile string) error {
	if !cl.e.stdoutTTY || cl.e.readSecret == nil {
		return errors.New("tui needs a terminal on stdin and stdout; for scripts use the other commands")
	}
	sock, err := cl.socketPath()
	if err != nil {
		return err
	}
	running, err := cl.daemonRunning(ctx)
	if err != nil {
		return err
	}
	opt := tui.Options{Connect: tui.DialSocket(sock), Socket: sock}
	if !running {
		dir, err := cl.dataDir()
		if err != nil {
			return err
		}
		if _, err := os.Stat(daemon.PathsFor(dir).Keystore); errors.Is(err, os.ErrNotExist) {
			return cl.notRunning(fmt.Sprintf("no socket at %s", sock))
		}
		if !embedded {
			embedded, err = cl.askYes(ctx, "openaimd is not running. Run it inside the TUI while it is open? [y/N] ")
			if err != nil {
				return err
			}
		}
		if embedded {
			d, err := cl.startEmbedded(ctx, dir, passFile)
			if err != nil {
				return err
			}
			defer d.Stop()
			opt.Embedded = true
		}
	}
	opt.Color = cl.e.getenv("NO_COLOR") == ""
	return tui.Run(ctx, opt, cl.e.stdin, cl.e.stdout)
}

// daemonRunning asks the daemon for its status.
func (cl *cli) daemonRunning(ctx context.Context) (bool, error) {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := unary(cctx, cl, rpcGetStatus, &pb.GetStatusRequest{})
	var ce *cliError
	if errors.As(err, &ce) && ce.code == exitNotRunning {
		return false, nil
	}
	return err == nil, err
}

// askYes asks a yes/no question on the terminal; no is the default. It
// reads stdin a byte at a time so nothing meant for the TUI is consumed,
// and gives up when ctx ends (Ctrl-C).
func (cl *cli) askYes(ctx context.Context, q string) (bool, error) {
	fmt.Fprint(cl.e.stderr, q)
	type answer struct {
		line string
		err  error
	}
	got := make(chan answer, 1)
	go func() {
		var line []byte
		b := make([]byte, 1)
		for {
			n, err := cl.e.stdin.Read(b)
			if n == 1 {
				if b[0] == '\n' {
					break
				}
				line = append(line, b[0])
			}
			if err == io.EOF {
				break
			} else if err != nil {
				got <- answer{err: err}
				return
			}
		}
		got <- answer{line: string(line)}
	}()
	select {
	case <-ctx.Done():
		fmt.Fprintln(cl.e.stderr)
		return false, &cliError{code: exitError, kind: "canceled", msg: "canceled"}
	case a := <-got:
		s := strings.ToLower(strings.TrimSpace(a.line))
		return s == "y" || s == "yes", a.err
	}
}

// startEmbedded unlocks the identity and serves the API from this process,
// on the usual socket, before the TUI takes the screen.
func (cl *cli) startEmbedded(ctx context.Context, dir, passFile string) (*api.Daemon, error) {
	var pass []byte
	var err error
	switch {
	case passFile != "":
		pass, err = cl.readPassphraseFile(passFile)
	case cl.e.getenv(envPassphrase) != "":
		pass = []byte(cl.e.getenv(envPassphrase))
	default:
		pass, err = cl.e.readSecret("Keystore passphrase: ")
		if err == nil && len(pass) == 0 {
			err = errors.New("empty passphrase")
		}
	}
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(cl.e.stderr, "Starting openaimd…")
	d, err := api.Start(ctx, api.Config{
		Config:     daemon.Config{DataDir: dir, Passphrase: pass},
		SocketPath: cl.g.socket,
	})
	if err != nil {
		return nil, fmt.Errorf("starting the embedded openaimd: %w", err)
	}
	return d, nil
}
