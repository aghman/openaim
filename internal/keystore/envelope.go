// Package keystore protects secrets at rest (design §5.5, spec/backup.md):
// the encrypted backup file, and the passphrase-encrypted file that holds
// the identity seed day to day when no OS keychain is used.
//
// Both use one envelope: Argon2id derives a key from the passphrase, and
// XChaCha20-Poly1305 encrypts the contents, with the whole header
// (including the Argon2id parameters) as associated data.
package keystore

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/text/unicode/norm"
)

// Envelope magics. Each file type has its own, and the magic is
// authenticated, so one kind can't be passed off as another.
const (
	MagicBackup   = "OAIMBAK1"
	MagicKeystore = "OAIMKEY1"
)

const (
	kdfArgon2id = 1
	saltLen     = 16
	headerLen   = 8 + 1 + 4 + 4 + 1 + saltLen + chacha20poly1305.NonceSizeX // 58
	// MaxPlaintext bounds what an envelope may hold.
	MaxPlaintext = 16 << 20
)

// Params are Argon2id cost parameters.
type Params struct {
	Time      uint32 // iterations
	MemoryKiB uint32
	Threads   uint8
}

// DefaultParams follow RFC 9106's second recommended option: t=3, 64 MiB,
// 4 lanes. That's roughly a quarter second on a laptop.
var DefaultParams = Params{Time: 3, MemoryKiB: 64 << 10, Threads: 4}

// Bounds accepted when opening, so a crafted file can't make us burn
// unbounded memory or time before the passphrase check fails.
const (
	minMemoryKiB = 8 << 10
	maxMemoryKiB = 1 << 20 // 1 GiB
	maxTime      = 16
	maxThreads   = 16
)

func (p Params) check() error {
	if p.Time < 1 || p.Time > maxTime || p.MemoryKiB < minMemoryKiB || p.MemoryKiB > maxMemoryKiB || p.Threads < 1 || p.Threads > maxThreads {
		return fmt.Errorf("%w: t=%d m=%d KiB p=%d", ErrParams, p.Time, p.MemoryKiB, p.Threads)
	}
	return nil
}

var (
	// ErrWrongPassphrase means the envelope didn't open: a wrong passphrase,
	// or a modified file. The two can't be told apart.
	ErrWrongPassphrase = errors.New("keystore: wrong passphrase or damaged file")
	// ErrFormat means the bytes aren't an envelope of the expected kind.
	ErrFormat = errors.New("keystore: not an OpenAIM file of this kind")
	// ErrParams means the Argon2id parameters are outside accepted bounds.
	ErrParams = errors.New("keystore: Argon2id parameters out of range")
	// ErrEmptyPassphrase is returned when sealing with an empty passphrase.
	ErrEmptyPassphrase = errors.New("keystore: empty passphrase")
)

// normalize puts the passphrase in Unicode NFC, so the same passphrase
// typed on different systems derives the same key.
func normalize(pass []byte) []byte { return norm.NFC.Bytes(pass) }

func deriveKey(pass, salt []byte, p Params) []byte {
	return argon2.IDKey(normalize(pass), salt, p.Time, p.MemoryKiB, p.Threads, chacha20poly1305.KeySize)
}

// Seal encrypts plaintext under passphrase into an envelope of kind magic.
func Seal(magic string, pass, plaintext []byte, p Params) ([]byte, error) {
	if len(magic) != 8 {
		return nil, fmt.Errorf("keystore: magic must be 8 bytes")
	}
	if len(pass) == 0 {
		return nil, ErrEmptyPassphrase
	}
	if err := p.check(); err != nil {
		return nil, err
	}
	if len(plaintext) > MaxPlaintext {
		return nil, fmt.Errorf("keystore: %d bytes is too large", len(plaintext))
	}
	hdr := make([]byte, headerLen)
	copy(hdr, magic)
	hdr[8] = kdfArgon2id
	binary.BigEndian.PutUint32(hdr[9:], p.Time)
	binary.BigEndian.PutUint32(hdr[13:], p.MemoryKiB)
	hdr[17] = p.Threads
	if _, err := rand.Read(hdr[18:]); err != nil { // salt and nonce
		return nil, err
	}
	salt, nonce := hdr[18:18+saltLen], hdr[18+saltLen:]
	aead, err := chacha20poly1305.NewX(deriveKey(pass, salt, p))
	if err != nil {
		return nil, err
	}
	return aead.Seal(hdr, nonce, plaintext, hdr), nil
}

// Open decrypts an envelope of kind magic.
func Open(magic string, pass, blob []byte) ([]byte, error) {
	if len(blob) < headerLen+chacha20poly1305.Overhead || string(blob[:8]) != magic {
		return nil, ErrFormat
	}
	if len(blob) > headerLen+MaxPlaintext+chacha20poly1305.Overhead {
		return nil, ErrFormat
	}
	if blob[8] != kdfArgon2id {
		return nil, fmt.Errorf("%w: KDF %d", ErrFormat, blob[8])
	}
	p := Params{
		Time:      binary.BigEndian.Uint32(blob[9:]),
		MemoryKiB: binary.BigEndian.Uint32(blob[13:]),
		Threads:   blob[17],
	}
	if err := p.check(); err != nil {
		return nil, err
	}
	hdr := blob[:headerLen]
	salt, nonce := hdr[18:18+saltLen], hdr[18+saltLen:]
	aead, err := chacha20poly1305.NewX(deriveKey(pass, salt, p))
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, blob[headerLen:], hdr)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return pt, nil
}
