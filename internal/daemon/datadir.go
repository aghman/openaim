package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// EnvDataDir overrides the default data directory.
const EnvDataDir = "OPENAIM_DATA_DIR"

// Files in the data directory.
const (
	DBFile       = "openaim.db"
	KeystoreFile = "identity.key" // spec/backup.md keystore (OAIMKEY1)
	SocketFile   = "openaimd.sock"
	LockFile     = "openaimd.pid"
	// NetworkFile is the bootstrap and relay list (ip.NetworkConfig JSON);
	// missing means the built-in defaults.
	NetworkFile = "network.json"
	// NetworkKeyFile is the fixed libp2p key of a --public node. Ordinary
	// nodes never write one: their network key is fresh every generation.
	NetworkKeyFile = "network.key"
)

// DefaultDataDir is where the daemon keeps its state unless told otherwise:
// $OPENAIM_DATA_DIR if set, else
//
//	macOS:   ~/Library/Application Support/openaim
//	Windows: %AppData%\openaim
//	others:  $XDG_DATA_HOME/openaim, or ~/.local/share/openaim
func DefaultDataDir() (string, error) {
	if d := os.Getenv(EnvDataDir); d != "" {
		return d, nil
	}
	switch runtime.GOOS {
	case "darwin", "ios":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Application Support", "openaim"), nil
	case "windows":
		d := os.Getenv("AppData")
		if d == "" {
			return "", errors.New("daemon: %AppData% is not set")
		}
		return filepath.Join(d, "openaim"), nil
	default:
		if d := os.Getenv("XDG_DATA_HOME"); d != "" && filepath.IsAbs(d) {
			return filepath.Join(d, "openaim"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".local", "share", "openaim"), nil
	}
}

// Paths are the files of one data directory.
type Paths struct {
	Dir      string
	DB       string
	Keystore string
	Socket   string
	Lock     string
	Network  string // NetworkFile
	NetKey   string // NetworkKeyFile
}

// PathsFor lays out the files in dir.
func PathsFor(dir string) Paths {
	return Paths{
		Dir:      dir,
		DB:       filepath.Join(dir, DBFile),
		Keystore: filepath.Join(dir, KeystoreFile),
		Socket:   filepath.Join(dir, SocketFile),
		Lock:     filepath.Join(dir, LockFile),
		Network:  filepath.Join(dir, NetworkFile),
		NetKey:   filepath.Join(dir, NetworkKeyFile),
	}
}

// prepareDir creates dir (mode 0700) if needed and refuses one that other
// users can get into: it holds the keystore and the API socket, and access to
// the socket is full control of the identity.
func prepareDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("daemon: data dir: %w", err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("daemon: data dir: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("daemon: data dir %s is not a directory", dir)
	}
	// TODO(windows): check the directory's ACL instead; mode bits mean
	// little there.
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("daemon: data dir %s is accessible by other users (mode %04o); run: chmod 700 %q",
			dir, fi.Mode().Perm(), dir)
	}
	return nil
}
