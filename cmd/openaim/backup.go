package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	pb "github.com/aghman/openaim/internal/apipb"
)

var cmdBackup = &command{
	name: "backup", synopsis: "export --out FILE [--force] [--show-phrase] [--passphrase-file FILE]",
	summary: "write an encrypted backup of the identity and buddy list",
	help: `The backup (spec/backup.md) holds the identity seed and the buddy list,
encrypted under a passphrase you choose. The passphrase comes from
--passphrase-file, else $OPENAIM_BACKUP_PASSPHRASE, else a terminal prompt
(asked twice); it is never taken as a command-line argument.

The file is written with mode 0600, atomically. An existing file is not
overwritten unless --force is given. --show-phrase also prints the 24-word
recovery phrase. The file may also be given as the argument after "export".
`,
	setup: func(fs *flag.FlagSet) runFunc {
		out := fs.String("out", "", "file to write the backup to")
		force := fs.Bool("force", false, "overwrite an existing file")
		showPhrase := fs.Bool("show-phrase", false, "also print the 24-word recovery phrase")
		passFile := fs.String("passphrase-file", "", "read the backup passphrase from this file")
		return func(ctx context.Context, cl *cli, args []string) error {
			if len(args) == 0 || args[0] != "export" {
				if len(args) == 0 {
					return usageErrorf("missing subcommand (export)")
				}
				return usageErrorf("unknown backup subcommand %q", args[0])
			}
			args = args[1:]
			if err := nargs(args, 0, 1); err != nil {
				return err
			}
			path := *out
			if len(args) == 1 {
				if path != "" {
					return usageErrorf("give the file once: --out or an argument")
				}
				path = args[0]
			}
			if path == "" {
				return usageErrorf("missing --out FILE")
			}
			return cl.backupExport(ctx, path, *force, *showPhrase, *passFile)
		}
	},
}

func (cl *cli) backupExport(ctx context.Context, path string, force, showPhrase bool, passFile string) error {
	if !force {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("%s exists; use --force to overwrite it", path)
		}
	}
	// Fail on a missing daemon before asking for a passphrase.
	if _, err := cl.client(); err != nil {
		return err
	}
	pass, err := cl.backupPassphrase(passFile)
	if err != nil {
		return err
	}
	defer clear(pass)
	r, err := unary(ctx, cl, rpcExportBackup, &pb.ExportBackupRequest{Passphrase: pass, IncludeRecoveryPhrase: showPhrase})
	if err != nil {
		return err
	}
	if err := writePrivateFile(path, r.GetBackup(), force); err != nil {
		return err
	}
	abs, _ := filepath.Abs(path)
	if cl.g.json {
		obj := map[string]any{"path": abs, "bytes": len(r.GetBackup())}
		if showPhrase {
			obj["recovery_phrase"] = r.GetRecoveryPhrase()
		}
		return cl.emit(obj)
	}
	fmt.Fprintf(cl.e.stdout, "Wrote encrypted backup to %s (%d bytes).\n", clean(abs), len(r.GetBackup()))
	fmt.Fprintln(cl.e.stdout, "Keep it and its passphrase safe: together they are your identity.")
	if showPhrase {
		fmt.Fprintln(cl.e.stdout)
		printPhrase(cl.e.stdout, r.GetRecoveryPhrase())
	}
	return nil
}

// backupPassphrase reads the passphrase from the file, the environment or
// the terminal (twice), in that order.
func (cl *cli) backupPassphrase(file string) ([]byte, error) {
	if file != "" {
		fi, err := os.Stat(file)
		if err != nil {
			return nil, fmt.Errorf("passphrase file: %w", err)
		}
		if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
			fmt.Fprintf(cl.e.stderr, "openaim: warning: %s is readable by other users (mode %04o)\n", clean(file), fi.Mode().Perm())
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("passphrase file: %w", err)
		}
		b = bytes.TrimSuffix(bytes.TrimSuffix(b, []byte("\n")), []byte("\r"))
		if len(b) == 0 {
			return nil, errors.New("passphrase file is empty")
		}
		return b, nil
	}
	if p := cl.e.getenv(EnvBackupPassphrase); p != "" {
		return []byte(p), nil
	}
	if cl.e.readSecret == nil {
		return nil, fmt.Errorf("no backup passphrase: use --passphrase-file or $%s when not on a terminal", EnvBackupPassphrase)
	}
	p, err := cl.e.readSecret("Backup passphrase: ")
	if err != nil {
		return nil, err
	}
	if len(p) == 0 {
		return nil, errors.New("empty passphrase")
	}
	again, err := cl.e.readSecret("Repeat passphrase: ")
	if err != nil {
		return nil, err
	}
	defer clear(again)
	if !bytes.Equal(p, again) {
		clear(p)
		return nil, errors.New("passphrases don't match")
	}
	return p, nil
}

// writePrivateFile writes data to path with mode 0600, atomically: a
// temporary file in the same directory is synced and then moved into place.
// Without force it never replaces an existing file, even one created while
// we were writing.
func writePrivateFile(path string, data []byte, force bool) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a rename; drops the extra link otherwise
	if err := f.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if force {
		err = os.Rename(tmp, path)
	} else if err = os.Link(tmp, path); err != nil {
		if _, serr := os.Lstat(path); serr == nil {
			return fmt.Errorf("%s exists; use --force to overwrite it", path)
		}
		// No hard links here (some filesystems): the existence check above
		// will have to do.
		err = os.Rename(tmp, path)
	}
	if err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync() // best effort: make the new name durable
		d.Close()
	}
	return nil
}
