// Command openaim is the scriptable OpenAIM client (design §11.3).
//
// It is a thin client of the openaimd API (proto/openaim/api/v1): every
// command maps to one or two RPCs and the daemon does the work. Buddies are
// named the way the daemon resolves them (identity key, key ID such as
// "~k3f9", petname or handle); the CLI passes the string through.
//
//	openaim [global flags] <command> [flags] [args]
//
// Run "openaim help" for the command list and "openaim help <command>" for
// one command. --json makes every command print one JSON object per result
// (one per line for watch), for scripts.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
	"google.golang.org/grpc"

	"github.com/aghman/openaim/internal/api"
	pb "github.com/aghman/openaim/internal/apipb"
	"github.com/aghman/openaim/internal/daemon"
)

// Exit codes. Scripts can branch on them.
const (
	exitOK         = 0
	exitError      = 1 // anything else
	exitUsage      = 2 // bad command line
	exitNotRunning = 3 // no daemon answers on the socket
	exitNotFound   = 4 // no such buddy (NOT_FOUND)
	exitExists     = 5 // the buddy is already on the list (ALREADY_EXISTS)
)

// EnvBackupPassphrase supplies the backup passphrase non-interactively.
const EnvBackupPassphrase = "OPENAIM_BACKUP_PASSPHRASE"

const defaultTimeout = 10 * time.Second

// env is the command's surroundings, so tests can run it in-process.
type env struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	getenv         func(string) string
	// stdoutTTY says stdout is a terminal (colors are allowed).
	stdoutTTY bool
	// readSecret reads a line without echo from the terminal; nil when
	// stdin isn't one.
	readSecret func(prompt string) ([]byte, error)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// run is the whole command: it parses args, talks to the daemon and returns
// the exit code.
func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return newEnv(stdin, stdout, stderr).run(ctx, args)
}

func newEnv(stdin io.Reader, stdout, stderr io.Writer) *env {
	e := &env{stdin: stdin, stdout: stdout, stderr: stderr, getenv: os.Getenv}
	if f, ok := stdout.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		e.stdoutTTY = true
	}
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fd := int(f.Fd())
		e.readSecret = func(prompt string) ([]byte, error) {
			fmt.Fprint(stderr, prompt)
			b, err := term.ReadPassword(fd)
			fmt.Fprintln(stderr)
			return b, err
		}
	}
	return e
}

// globals are the flags every command takes, before or after its name.
type globals struct {
	dataDir string
	socket  string
	json    bool
	timeout time.Duration
}

func (g *globals) register(fs *flag.FlagSet) {
	// Defaults are the current values, so a flag given before the command
	// survives registering the set again for the command.
	fs.StringVar(&g.dataDir, "data-dir", g.dataDir, "daemon data directory (default: $OPENAIM_DATA_DIR, else per-OS)")
	fs.StringVar(&g.socket, "socket", g.socket, "daemon API socket (default: openaimd.sock in the data dir)")
	fs.BoolVar(&g.json, "json", g.json, "print machine-readable JSON, one object per result")
	fs.DurationVar(&g.timeout, "timeout", g.timeout, "how long to wait for the daemon to answer")
}

// cli is one invocation.
type cli struct {
	e    *env
	g    globals
	cmd  string
	conn *grpc.ClientConn
	sock string
}

func (e *env) run(ctx context.Context, args []string) int {
	cl := &cli{e: e, g: globals{timeout: defaultTimeout}}
	defer func() {
		if cl.conn != nil {
			cl.conn.Close()
		}
	}()

	top := flag.NewFlagSet("openaim", flag.ContinueOnError)
	top.SetOutput(io.Discard)
	cl.g.register(top)
	if err := top.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			cl.printUsage(e.stdout)
			return exitOK
		}
		return cl.fail(usageErrorf("%v", err))
	}
	rest := top.Args()
	if len(rest) == 0 {
		cl.printUsage(e.stderr)
		return exitUsage
	}
	cl.cmd = rest[0]
	c, ok := commandByName(cl.cmd)
	if !ok {
		cl.cmd = ""
		return cl.fail(usageErrorf("unknown command %q", rest[0]))
	}
	fs := cl.flags(c)
	runCmd := c.setup(fs)
	pos, err := cl.parse(c, fs, rest[1:])
	if err != nil {
		return cl.fail(err)
	}
	return cl.fail(runCmd(ctx, cl, pos))
}

// runFunc runs a command with its positional arguments, after its flags are
// parsed.
type runFunc func(ctx context.Context, cl *cli, args []string) error

// command is one subcommand.
type command struct {
	name     string
	synopsis string // arguments, for the usage line
	summary  string // one line, for the command list
	help     string // the rest of the command's help
	// noIntersperse stops flag parsing at the first argument, so the rest
	// can be free text (send).
	noIntersperse bool
	// setup registers the command's flags and returns what runs it.
	setup func(fs *flag.FlagSet) runFunc
}

var commands []*command

func init() {
	commands = []*command{
		cmdStatus, cmdBuddies, cmdAdd, cmdInvite, cmdAccept, cmdDecline, cmdBlock, cmdRename, cmdRemove, cmdVerify, cmdSend, cmdHistory,
		cmdAway, cmdBack, cmdWatch, cmdTUI, cmdBackup, cmdShutdown, cmdVersion, cmdHelp,
	}
}

func commandByName(name string) (*command, bool) {
	for _, c := range commands {
		if c.name == name {
			return c, true
		}
	}
	return nil, false
}

const usageHead = `openaim: the OpenAIM command-line client (talks to a running openaimd)

Usage:
  openaim [global flags] <command> [flags] [args]

Commands:
`

const usageTail = `
Global flags (before or after the command):
  --data-dir DIR    daemon data directory (default: $OPENAIM_DATA_DIR, else per-OS)
  --socket PATH     daemon API socket (default: openaimd.sock in the data dir)
  --json            machine-readable output: one JSON object per result
                    (one per line for watch); errors go to stderr as JSON
  --timeout DUR     how long to wait for the daemon (default 10s)

A buddy is named by its identity key, key ID (e.g. ~k3f9), petname or handle.

Exit codes:
  0  success              3  openaimd is not running
  1  error                4  no such buddy
  2  usage error          5  buddy already on the list

Run "openaim help <command>" for a command's details.
`

func (cl *cli) printUsage(w io.Writer) {
	var b strings.Builder
	b.WriteString(usageHead)
	t := &table{}
	for _, c := range commands {
		t.row(cell{text: "  " + c.name + " " + c.synopsis}, cell{text: c.summary})
	}
	t.write(&b, style{})
	b.WriteString(usageTail)
	io.WriteString(w, b.String())
}

func (cl *cli) printCommandHelp(w io.Writer, c *command, fs *flag.FlagSet) {
	fmt.Fprintf(w, "Usage: openaim %s %s\n\n%s.\n", c.name, c.synopsis, upperFirst(c.summary))
	if c.help != "" {
		fmt.Fprintf(w, "\n%s", c.help)
	}
	fmt.Fprintln(w, "\nFlags (with the global flags):")
	fs.SetOutput(w)
	fs.PrintDefaults()
	fs.SetOutput(io.Discard)
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

var cmdHelp = &command{
	name: "help", synopsis: "[command]", summary: "show help for openaim or one command",
	setup: func(*flag.FlagSet) runFunc {
		return func(_ context.Context, cl *cli, args []string) error {
			if err := nargs(args, 0, 1); err != nil {
				return err
			}
			if len(args) == 0 {
				cl.printUsage(cl.e.stdout)
				return nil
			}
			c, ok := commandByName(args[0])
			if !ok {
				return usageErrorf("unknown command %q", args[0])
			}
			fs := cl.flags(c)
			c.setup(fs)
			cl.printCommandHelp(cl.e.stdout, c, fs)
			return nil
		}
	},
}

// flags is a flag set for c with the global flags registered.
func (cl *cli) flags(c *command) *flag.FlagSet {
	fs := flag.NewFlagSet(c.name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cl.g.register(fs)
	return fs
}

// parse parses a command's flags. Flags may follow positional arguments
// (until "--"), unless the command says otherwise: then parsing stops at the
// first positional argument and everything after it is an argument.
func (cl *cli) parse(c *command, fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				cl.printCommandHelp(cl.e.stdout, c, fs)
				return nil, errHelpShown
			}
			return nil, usageErrorf("%v", err)
		}
		rest := fs.Args()
		consumed := args[:len(args)-len(rest)]
		if len(rest) == 0 {
			return pos, nil
		}
		if c.noIntersperse || (len(consumed) > 0 && consumed[len(consumed)-1] == "--") {
			return append(pos, rest...), nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// nargs checks the number of positional arguments; max < 0 means no limit.
func nargs(args []string, min, max int) error {
	if len(args) < min {
		return usageErrorf("missing argument")
	}
	if max >= 0 && len(args) > max {
		return usageErrorf("unexpected argument %q", args[max])
	}
	return nil
}

// dataDir resolves the data directory like openaimd does: the flag, else
// $OPENAIM_DATA_DIR, else the per-OS default.
func (cl *cli) dataDir() (string, error) {
	d := cl.g.dataDir
	if d == "" {
		d = cl.e.getenv(daemon.EnvDataDir)
	}
	if d == "" {
		var err error
		if d, err = daemon.DefaultDataDir(); err != nil {
			return "", err
		}
	}
	return filepath.Abs(d)
}

func (cl *cli) socketPath() (string, error) {
	if cl.sock != "" {
		return cl.sock, nil
	}
	if cl.g.socket != "" {
		cl.sock = cl.g.socket
		return cl.sock, nil
	}
	dir, err := cl.dataDir()
	if err != nil {
		return "", err
	}
	cl.sock = daemon.PathsFor(dir).Socket
	return cl.sock, nil
}

// client connects to the daemon. A missing socket means it isn't running.
func (cl *cli) client() (pb.DaemonClient, error) {
	sock, err := cl.socketPath()
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(sock); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return nil, cl.notRunning(fmt.Sprintf("no socket at %s", sock))
	}
	if cl.conn == nil {
		if cl.conn, err = api.Dial(sock); err != nil {
			return nil, err
		}
	}
	return pb.NewDaemonClient(cl.conn), nil
}

// notRunning explains a missing daemon, and suggests init if the data dir
// has no identity at all.
func (cl *cli) notRunning(why string) error {
	msg := fmt.Sprintf("openaimd is not running (%s); start it with `openaimd run`", why)
	if cl.g.socket == "" {
		if dir, err := cl.dataDir(); err == nil {
			if _, err := os.Stat(daemon.PathsFor(dir).Keystore); errors.Is(err, os.ErrNotExist) {
				msg = fmt.Sprintf("openaimd is not running (%s), and %s has no identity; create one with `openaimd init`, then start it with `openaimd run`", why, dir)
			}
		}
	}
	return &cliError{code: exitNotRunning, kind: "not_running", msg: msg}
}

// call is the context for one unary RPC.
func (cl *cli) call(ctx context.Context) (context.Context, context.CancelFunc) {
	if cl.g.timeout > 0 {
		return context.WithTimeout(ctx, cl.g.timeout)
	}
	return context.WithCancel(ctx)
}
