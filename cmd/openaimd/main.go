// Command openaimd is the OpenAIM daemon (design §3). It owns the identity,
// the buddy list, the message store and (later) the transports, and serves
// the local client API that the CLI, TUI and GUI use.
//
//	openaimd init [--restore]   create an identity (or restore one from its phrase)
//	openaimd [run]              unlock the identity and serve the API
//	openaimd version
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/aghman/openaim/internal/api"
	"github.com/aghman/openaim/internal/daemon"
	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/keystore"
)

// EnvPassphrase supplies the keystore passphrase non-interactively.
const EnvPassphrase = "OPENAIM_PASSPHRASE"

const usage = `openaimd: the OpenAIM daemon

Usage:
  openaimd init [--restore] [flags]   create an identity, or restore one from its recovery phrase
  openaimd [run] [flags]              unlock the identity and serve the local API
  openaimd version                    print the version

Common flags:
  --data-dir DIR          data directory (default: $OPENAIM_DATA_DIR, else per-OS)
  --passphrase-file FILE  read the keystore passphrase from FILE

The passphrase comes from --passphrase-file, else $OPENAIM_PASSPHRASE, else a
terminal prompt. It is never taken as a command-line argument.
Run "openaimd <command> -h" for a command's flags.
`

// keystoreParams are the Argon2id costs for a new keystore. Tests lower them.
var keystoreParams keystore.Params

// env is the command's surroundings, so tests can run it in-process.
type env struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	getenv         func(string) string
	// readSecret reads a line without echo from a terminal; nil when stdin
	// isn't one.
	readSecret func(prompt string) ([]byte, error)
}

func main() {
	e := env{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, getenv: os.Getenv}
	if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
		e.readSecret = func(prompt string) ([]byte, error) {
			fmt.Fprint(os.Stderr, prompt)
			b, err := term.ReadPassword(fd)
			fmt.Fprintln(os.Stderr)
			return b, err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], e))
}

func run(ctx context.Context, args []string, e env) int {
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "run":
		err = runDaemon(ctx, args, e)
	case "init":
		err = runInit(ctx, args, e)
	case "version":
		fmt.Fprintln(e.stdout, "openaimd", daemon.BuildVersion())
	case "help":
		fmt.Fprint(e.stdout, usage)
	default:
		fmt.Fprintf(e.stderr, "openaimd: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp):
		return 0
	case errors.Is(err, errUsage):
		return 2
	default:
		fmt.Fprintln(e.stderr, "openaimd:", err)
		return 1
	}
}

var errUsage = errors.New("usage")

// common holds the flags every command takes.
type common struct {
	dataDir        string
	passphraseFile string
	logLevel       string
	logJSON        bool
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.dataDir, "data-dir", "", "data directory (default: $OPENAIM_DATA_DIR, else per-OS)")
	fs.StringVar(&c.passphraseFile, "passphrase-file", "", "read the keystore passphrase from this file")
	fs.StringVar(&c.logLevel, "log-level", "info", "log level: debug, info, warn or error")
	fs.BoolVar(&c.logJSON, "log-json", false, "log JSON lines instead of text")
}

func parse(fs *flag.FlagSet, args []string, e env) error {
	fs.SetOutput(e.stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(e.stderr, "openaimd %s: unexpected argument %q\n", fs.Name(), fs.Arg(0))
		return errUsage
	}
	return nil
}

func (c *common) resolveDataDir(e env) (string, error) {
	d := c.dataDir
	if d == "" {
		d = e.getenv(daemon.EnvDataDir)
	}
	if d == "" {
		var err error
		if d, err = daemon.DefaultDataDir(); err != nil {
			return "", err
		}
	}
	return filepath.Abs(d)
}

func (c *common) logger(e env) (*slog.Logger, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(c.logLevel)); err != nil {
		return nil, fmt.Errorf("--log-level: %w", err)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if c.logJSON {
		return slog.New(slog.NewJSONHandler(e.stderr, opts)), nil
	}
	return slog.New(slog.NewTextHandler(e.stderr, opts)), nil
}

// passphrase gets the keystore passphrase from the file, the environment or
// the terminal, in that order. confirm asks twice on a terminal.
func (c *common) passphrase(e env, confirm bool) ([]byte, error) {
	if c.passphraseFile != "" {
		fi, err := os.Stat(c.passphraseFile)
		if err != nil {
			return nil, fmt.Errorf("passphrase file: %w", err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			fmt.Fprintf(e.stderr, "openaimd: warning: %s is readable by other users (mode %04o)\n", c.passphraseFile, fi.Mode().Perm())
		}
		b, err := os.ReadFile(c.passphraseFile)
		if err != nil {
			return nil, fmt.Errorf("passphrase file: %w", err)
		}
		b = bytes.TrimSuffix(bytes.TrimSuffix(b, []byte("\n")), []byte("\r"))
		if len(b) == 0 {
			return nil, errors.New("passphrase file is empty")
		}
		return b, nil
	}
	if p := e.getenv(EnvPassphrase); p != "" {
		return []byte(p), nil
	}
	if e.readSecret == nil {
		return nil, fmt.Errorf("no passphrase: use --passphrase-file or $%s when not on a terminal", EnvPassphrase)
	}
	p, err := e.readSecret("Keystore passphrase: ")
	if err != nil {
		return nil, err
	}
	if len(p) == 0 {
		return nil, errors.New("empty passphrase")
	}
	if confirm {
		again, err := e.readSecret("Repeat passphrase: ")
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(p, again) {
			return nil, errors.New("passphrases don't match")
		}
	}
	return p, nil
}

func runDaemon(ctx context.Context, args []string, e env) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var c common
	c.register(fs)
	socket := fs.String("socket", "", "API socket path (default: openaimd.sock in the data dir)")
	if err := parse(fs, args, e); err != nil {
		return err
	}
	log, err := c.logger(e)
	if err != nil {
		return err
	}
	dir, err := c.resolveDataDir(e)
	if err != nil {
		return err
	}
	pass, err := c.passphrase(e, false)
	if err != nil {
		return err
	}
	err = api.Run(ctx, api.Config{
		Config:     daemon.Config{DataDir: dir, Passphrase: pass, KeystoreParams: keystoreParams, Logger: log},
		SocketPath: *socket,
	})
	if errors.Is(err, daemon.ErrNotInitialized) {
		return fmt.Errorf("%w\n(data dir: %s)", err, dir)
	}
	return err
}

func runInit(ctx context.Context, args []string, e env) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	var c common
	c.register(fs)
	restore := fs.Bool("restore", false, "restore an identity from its 24-word recovery phrase (read from stdin)")
	if err := parse(fs, args, e); err != nil {
		return err
	}
	dir, err := c.resolveDataDir(e)
	if err != nil {
		return err
	}
	var phrase string
	if *restore {
		if phrase, err = readPhrase(e); err != nil {
			return err
		}
		// Check it before asking for a passphrase.
		if _, err := identity.ParsePhrase(phrase); err != nil {
			return err
		}
	}
	pass, err := c.passphrase(e, true)
	if err != nil {
		return err
	}
	id, err := daemon.Init(ctx, daemon.InitConfig{DataDir: dir, Passphrase: pass, Phrase: phrase, KeystoreParams: keystoreParams})
	if err != nil {
		return err
	}
	pub := id.Public()
	if *restore {
		fmt.Fprintf(e.stdout, "Restored identity %s\n  key: %s\n  data dir: %s\n", pub.KeyID(), pub, dir)
		return nil
	}
	fmt.Fprintf(e.stdout, "Created identity %s\n  key: %s\n  data dir: %s\n\n", pub.KeyID(), pub, dir)
	printPhrase(e.stdout, id.Phrase())
	return nil
}

// readPhrase reads the recovery phrase: one line from a terminal (echo off,
// since it is the identity's secret), or all of stdin otherwise.
func readPhrase(e env) (string, error) {
	if e.readSecret != nil {
		b, err := e.readSecret("Recovery phrase (24 words): ")
		return string(b), err
	}
	b, err := io.ReadAll(io.LimitReader(e.stdin, 4096))
	if err != nil {
		return "", err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return "", errors.New("no recovery phrase on stdin")
	}
	return string(b), nil
}

func printPhrase(w io.Writer, phrase string) {
	words := strings.Fields(phrase)
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	fmt.Fprintln(bw, "RECOVERY PHRASE: write these 24 words down and keep them somewhere safe.")
	fmt.Fprintln(bw, "Anyone who has them can become you. They are shown only this once, and")
	fmt.Fprintln(bw, "they are the only way to recover this identity if the device is lost.")
	fmt.Fprintln(bw)
	for i := 0; i < len(words); i += 4 {
		for j := i; j < i+4 && j < len(words); j++ {
			fmt.Fprintf(bw, "  %2d. %-10s", j+1, words[j])
		}
		fmt.Fprintln(bw)
	}
	fmt.Fprintln(bw)
}
