// Command openaimd is the OpenAIM daemon (design §3). It owns the identity,
// the buddy list, the message store and the transports, and serves the
// local client API that the CLI, TUI and GUI use.
//
//	openaimd init --backup FILE create an identity and its recovery key (kept only in FILE)
//	openaimd init --restore     restore an identity from its phrase (no recovery key)
//	openaimd init --restore-backup FILE   restore an identity and its recovery key
//	openaimd [run]              unlock the identity, join the network and serve the API
//	openaimd network init       write network.json (bootstrap and relay nodes) to edit
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

	ma "github.com/multiformats/go-multiaddr"
	"golang.org/x/term"

	"github.com/aghman/openaim/internal/api"
	"github.com/aghman/openaim/internal/daemon"
	"github.com/aghman/openaim/internal/handle"
	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/invite"
	"github.com/aghman/openaim/internal/keystore"
	"github.com/aghman/openaim/internal/transport/ip"
)

// EnvPassphrase supplies the keystore passphrase non-interactively.
const EnvPassphrase = "OPENAIM_PASSPHRASE"

const usage = `openaimd: the OpenAIM daemon

Usage:
  openaimd init --backup FILE [flags] create an identity; FILE gets the first backup,
                                      the only copy of its recovery key
  openaimd init --restore [flags]     restore an identity from its recovery phrase
  openaimd init --restore-backup FILE restore an identity from a backup file
  openaimd [run] [flags]              unlock the identity, join the network and
                                      serve the local API
  openaimd network init [flags]       write the network config template (network.json)
  openaimd version                    print the version

Common flags:
  --data-dir DIR          data directory (default: $OPENAIM_DATA_DIR, else per-OS)
  --passphrase-file FILE  read the keystore passphrase from FILE
  --keystore MODE         where the identity seed lives: file, keychain or auto

The seed is kept in a passphrase-encrypted file in the data directory by
default. --keystore=keychain keeps it in the OS keychain instead (macOS
Keychain, Secret Service, Windows Credential Manager): no passphrase to type,
but any program running as you in an unlocked session can read it, so it
protects the seed less than the file does. --keystore=auto uses the keychain
when one is available, else the file. init records the choice; run uses it,
and refuses a --keystore that names a different one.

The passphrase (file keystore only) comes from --passphrase-file, else
$OPENAIM_PASSPHRASE, else a terminal prompt. It is never taken as a
command-line argument.
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
	case "network":
		err = runNetwork(args, e)
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
	keystore       string
}

// keystoreHelp explains --keystore; see also usage.
const keystoreHelp = "where the identity seed is kept: file (passphrase-encrypted file in the data dir), " +
	"keychain (the OS keychain: no passphrase, but any program running as you can read it, so weaker), " +
	"or auto (the keychain if one is available, else the file)"

// keystoreMode parses --keystore.
func (c *common) keystoreMode() (daemon.KeystoreMode, error) {
	m, err := daemon.ParseKeystoreMode(c.keystore)
	if err != nil {
		return "", fmt.Errorf("--keystore: %w", err)
	}
	return m, nil
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
	return readPassphrase(e, secretSource{
		file: c.passphraseFile, fileFlag: "--passphrase-file", env: EnvPassphrase, what: "Keystore passphrase",
	}, confirm)
}

// secretSource names where one passphrase may come from.
type secretSource struct {
	file     string // the flag's value
	fileFlag string // e.g. "--passphrase-file"
	env      string // environment variable
	what     string // prompt, e.g. "Keystore passphrase"
}

// readPassphrase reads a passphrase from the file, the environment or the
// terminal, in that order. confirm asks twice on a terminal.
func readPassphrase(e env, src secretSource, confirm bool) ([]byte, error) {
	if src.file != "" {
		fi, err := os.Stat(src.file)
		if err != nil {
			return nil, fmt.Errorf("passphrase file: %w", err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			fmt.Fprintf(e.stderr, "openaimd: warning: %s is readable by other users (mode %04o)\n", src.file, fi.Mode().Perm())
		}
		b, err := os.ReadFile(src.file)
		if err != nil {
			return nil, fmt.Errorf("passphrase file: %w", err)
		}
		b = bytes.TrimSuffix(bytes.TrimSuffix(b, []byte("\n")), []byte("\r"))
		if len(b) == 0 {
			return nil, errors.New("passphrase file is empty")
		}
		return b, nil
	}
	if p := e.getenv(src.env); p != "" {
		return []byte(p), nil
	}
	if e.readSecret == nil {
		return nil, fmt.Errorf("no %s: use %s or $%s when not on a terminal", strings.ToLower(src.what), src.fileFlag, src.env)
	}
	p, err := e.readSecret(src.what + ": ")
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
	fs.StringVar(&c.keystore, "keystore", "", keystoreHelp+
		"; must match what init chose, and auto accepts it (default: what init chose)")
	socket := fs.String("socket", "", "API socket path (default: openaimd.sock in the data dir)")
	registry := fs.String("registry", "", "default handle registry domain: handles one label under it show as just that label (default: none)")
	displayName := fs.String("display-name", "", "the name your buddy requests and accepts offer (at most 64 bytes)")
	contactHint := fs.String("contact-hint", "", "contact hint for invite links: a relay-circuit or mailbox multiaddr, never your own IP address")
	offline := fs.Bool("offline", false, "don't join the network: messages stay queued (for maintenance)")
	public := fs.Bool("public", false, "run a public relay and DHT bootstrap node: a fixed peer ID (network.key in the data dir), "+
		"DHT server mode and a circuit relay service; for operators of publicly reachable machines")
	natPortMap := fs.Bool("upnp", false, "try to open a port on the home router with UPnP / NAT-PMP")
	var listen []string
	fs.Func("listen", "multiaddr to listen on; repeat for each (default: TCP and QUIC on random ports, all interfaces)", func(s string) error {
		listen = append(listen, s)
		return nil
	})
	fcRate := fs.Float64("first-contact-rate", daemon.DefaultFirstContactRate, "incoming first-contact frames allowed per second, per transport")
	fcBurst := fs.Int("first-contact-burst", daemon.DefaultFirstContactBurst, "incoming first-contact frames allowed in a burst, per transport")
	var resolvers []string
	fs.Func("doh-resolver", "DNS-over-HTTPS resolver URL for handle lookups; repeat for each (at least two; default: "+
		strings.Join(handle.DefaultResolvers, ", ")+")", func(s string) error {
		resolvers = append(resolvers, s)
		return nil
	})
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
	mode, err := c.keystoreMode()
	if err != nil {
		return err
	}
	var hint func() string
	if *contactHint != "" {
		a, err := invite.CheckContactHint(*contactHint)
		if err != nil {
			return fmt.Errorf("--contact-hint: %w", err)
		}
		s := a.String()
		hint = func() string { return s }
	}
	if *fcRate <= 0 || *fcBurst <= 0 {
		return errors.New("--first-contact-rate and --first-contact-burst must be positive")
	}
	var network *daemon.NetworkOptions
	switch {
	case *offline && (*public || len(listen) > 0 || *natPortMap):
		fmt.Fprintln(e.stderr, "openaimd run: --offline takes no network flags")
		return errUsage
	case !*offline:
		for _, l := range listen {
			if _, err := ma.NewMultiaddr(l); err != nil {
				return fmt.Errorf("--listen %q: %w", l, err)
			}
		}
		// Read network.json now, so a broken file is a clear error.
		if _, err := ip.LoadNetworkConfig(daemon.PathsFor(dir).Network); err != nil {
			return fmt.Errorf("network config: %w (fix it, or rewrite it with openaimd network init --force)", err)
		}
		network = &daemon.NetworkOptions{Listen: listen, Public: *public, NATPortMap: *natPortMap}
	}
	err = api.Run(ctx, api.Config{
		Config: daemon.Config{
			DataDir: dir, Keystore: mode, KeystoreParams: keystoreParams, Logger: log,
			// Asked only if the identity uses the file keystore.
			PassphraseFunc: func() ([]byte, error) { return c.passphrase(e, false) },
			HandleRegistry: *registry, DoHResolvers: resolvers,
			DisplayName: *displayName, ContactHint: hint, FirstContactRate: *fcRate, FirstContactBurst: *fcBurst,
			Network: network,
		},
		SocketPath: *socket,
	})
	if errors.Is(err, daemon.ErrNotInitialized) {
		return fmt.Errorf("%w\n(data dir: %s)", err, dir)
	}
	return err
}

// EnvBackupPassphrase supplies the backup passphrase non-interactively (the
// same variable `openaim backup export` reads).
const EnvBackupPassphrase = "OPENAIM_BACKUP_PASSPHRASE"

// maxBackupFile bounds a backup file read for --restore-backup.
const maxBackupFile = keystore.MaxPlaintext + 1024

const initHelp = `Usage: openaimd init --backup FILE [flags]
       openaimd init --no-recovery-key [flags]
       openaimd init --restore [flags]               (phrase on stdin or the terminal)
       openaimd init --restore-backup FILE [flags]

A new identity gets a recovery key (design §5.5): a second key, used only to
sign a key rotation if this device is ever lost or stolen. Its secret is kept
ONLY in an encrypted backup file, never in the keystore, the keychain or the
database, so a stolen device can't use it. init therefore writes that first
backup to --backup FILE, under a backup passphrase (--backup-passphrase-file,
else $OPENAIM_BACKUP_PASSPHRASE, else a terminal prompt). Move the file off
this device. Later backups (openaim backup export --from FILE) carry the
recovery key over only from a backup that has it: lose every copy and the
identity can never rotate. --no-recovery-key skips all this.

--restore takes the 24-word phrase, which restores the identity key only: the
phrase doesn't encode the recovery key, so the restored identity has none.
--restore-backup restores the identity, its recovery key and the buddy list
from a backup file instead (the file keeps the recovery seed; nothing new is
written).

Flags:
`

func runInit(ctx context.Context, args []string, e env) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), initHelp)
		fs.PrintDefaults()
	}
	var c common
	c.register(fs)
	fs.StringVar(&c.keystore, "keystore", string(daemon.KeystoreModeFile), keystoreHelp)
	restore := fs.Bool("restore", false, "restore an identity from its 24-word recovery phrase (read from stdin); it gets no recovery key")
	restoreBackup := fs.String("restore-backup", "", "restore the identity, recovery key and buddy list from this backup file")
	backupOut := fs.String("backup", "", "write the first backup, which alone holds the recovery key, to this new file (required for a new identity unless --no-recovery-key)")
	backupPassFile := fs.String("backup-passphrase-file", "", "read the backup passphrase from this file")
	noRecovery := fs.Bool("no-recovery-key", false, "create the identity without a recovery key (it can never sign a key rotation)")
	if err := parse(fs, args, e); err != nil {
		return err
	}
	switch {
	case *restore && *restoreBackup != "":
		fmt.Fprintln(e.stderr, "openaimd init: give --restore or --restore-backup, not both")
		return errUsage
	case (*restore || *restoreBackup != "") && (*backupOut != "" || *noRecovery):
		fmt.Fprintln(e.stderr, "openaimd init: a restore makes no recovery key: drop --backup and --no-recovery-key")
		return errUsage
	case *backupOut != "" && *noRecovery:
		fmt.Fprintln(e.stderr, "openaimd init: give --backup or --no-recovery-key, not both")
		return errUsage
	case !*restore && *restoreBackup == "" && *backupOut == "" && !*noRecovery:
		return errors.New("init needs --backup FILE: the new identity's recovery key is kept only in that encrypted " +
			"backup file (keep it off this device), or --no-recovery-key to go without one (see openaimd init -h)")
	}
	dir, err := c.resolveDataDir(e)
	if err != nil {
		return err
	}
	backupSrc := secretSource{file: *backupPassFile, fileFlag: "--backup-passphrase-file", env: EnvBackupPassphrase, what: "Backup passphrase"}
	cfg := daemon.InitConfig{DataDir: dir, KeystoreParams: keystoreParams}
	switch {
	case *restore:
		if cfg.Phrase, err = readPhrase(e); err != nil {
			return err
		}
		// Check it before asking for a passphrase.
		if _, err := identity.ParsePhrase(cfg.Phrase); err != nil {
			return err
		}
	case *restoreBackup != "":
		blob, err := readBackupFile(*restoreBackup)
		if err != nil {
			return err
		}
		pass, err := readPassphrase(e, backupSrc, false)
		if err != nil {
			return err
		}
		if cfg.FromBackup, err = keystore.DecodeBackup(blob, pass); err != nil {
			return fmt.Errorf("backup %s: %w", *restoreBackup, err)
		}
	case *backupOut != "":
		if _, err := os.Lstat(*backupOut); err == nil {
			return fmt.Errorf("%s exists; give a new file for the backup", *backupOut)
		}
		cfg.BackupPath = *backupOut
	}
	mode, err := c.keystoreMode()
	if err != nil {
		return err
	}
	if mode, err = daemon.ResolveKeystoreMode(mode); err != nil {
		return err
	}
	cfg.Keystore = mode
	where := "OS keychain (no passphrase; readable by programs running as you)"
	if mode == daemon.KeystoreModeFile {
		if cfg.Passphrase, err = c.passphrase(e, true); err != nil {
			return err
		}
		where = "passphrase-encrypted file " + daemon.PathsFor(dir).Keystore
	}
	if cfg.BackupPath != "" {
		if cfg.BackupPassphrase, err = readPassphrase(e, backupSrc, true); err != nil {
			return err
		}
		if bytes.Equal(cfg.BackupPassphrase, cfg.Passphrase) {
			fmt.Fprintln(e.stderr, "openaimd: warning: the backup passphrase is the keystore passphrase; "+
				"anyone who learns it and finds the backup can rotate your key")
		}
	}
	res, err := daemon.InitIdentity(ctx, cfg)
	if err != nil {
		return err
	}
	id := res.Identity
	pub := id.Public()
	verb := "Created"
	if *restore || *restoreBackup != "" {
		verb = "Restored"
	}
	bw := bufio.NewWriter(e.stdout)
	fmt.Fprintf(bw, "%s identity %s\n  key: %s\n  data dir: %s\n  keystore: %s\n", verb, pub.KeyID(), pub, dir, where)
	if res.RecoveryKey != nil {
		fmt.Fprintf(bw, "  recovery key: %s (%s)\n", res.RecoveryKey, res.RecoveryKey.KeyID())
	} else {
		fmt.Fprintln(bw, "  recovery key: none (this identity can't sign a key rotation)")
	}
	if *restoreBackup != "" {
		fmt.Fprintf(bw, "  buddies restored: %d\n", res.Buddies)
	}
	if res.BackupPath != "" {
		fmt.Fprintf(bw, "  backup: %s\n\n", res.BackupPath)
		fmt.Fprintln(bw, "The backup file is the ONLY copy of the recovery key. Move it off this device")
		fmt.Fprintln(bw, "and keep it with its passphrase. Later backups keep the recovery key only if")
		fmt.Fprintln(bw, "made from this one: openaim backup export --from FILE.")
	}
	bw.Flush()
	if verb == "Created" {
		fmt.Fprintln(e.stdout)
		printPhrase(e.stdout, id.Phrase())
	}
	return nil
}

// readBackupFile reads a backup file, refusing anything too large to be one.
func readBackupFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("backup: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxBackupFile+1))
	if err != nil {
		return nil, fmt.Errorf("backup: %w", err)
	}
	if len(b) > maxBackupFile {
		return nil, fmt.Errorf("backup: %s is too large to be a backup file", path)
	}
	return b, nil
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

const networkHelp = `Usage: openaimd network init [--force] [--data-dir DIR]

Writes network.json, the list of DHT bootstrap nodes and circuit relays the
daemon starts from, into the data directory, as a template to edit. Without
the file the daemon uses the same built-in list. NO COMMUNITY NODES ARE
OPERATED YET, so the lists are empty: add nodes you run (openaimd run
--public on a publicly reachable machine) or trust. Each entry is a
multiaddr ending in /p2p/<peer ID>; a list in the file replaces the
built-in one, and a list left out keeps it. Restart the daemon to apply.

Flags:
`

// runNetwork is "openaimd network init".
func runNetwork(args []string, e env) error {
	if len(args) == 0 || args[0] != "init" {
		fmt.Fprint(e.stderr, networkHelp)
		return errUsage
	}
	fs := flag.NewFlagSet("network init", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), networkHelp)
		fs.PrintDefaults()
	}
	dataDir := fs.String("data-dir", "", "data directory (default: $OPENAIM_DATA_DIR, else per-OS)")
	force := fs.Bool("force", false, "replace an existing network.json")
	if err := parse(fs, args[1:], e); err != nil {
		return err
	}
	c := common{dataDir: *dataDir}
	dir, err := c.resolveDataDir(e)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := daemon.PathsFor(dir).Network
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if *force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%s exists; edit it, or give --force to replace it with the template", path)
	} else if err != nil {
		return err
	}
	if _, err := f.Write(ip.DefaultNetworkConfigJSON()); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "Wrote %s\n", path)
	return nil
}
