package identity

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// The recovery phrase (design §5.5, spec/wire.md §4.5) is the 32-byte
// identity seed written as 24 words from the BIP-39 English list: the seed's
// 256 bits plus an 8-bit checksum (the first byte of SHA-256(seed)), cut into
// 24 groups of 11 bits, most significant bit first.
//
// This is BIP-39's mnemonic encoding only. The words encode the seed
// directly; there is no PBKDF2 step and no passphrase.

// PhraseWords is the number of words in a recovery phrase.
const PhraseWords = 24

//go:embed wordlist/english.txt
var wordlistFile string

const wordlistSHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

var (
	wordsOnce sync.Once
	words     []string
	wordIndex map[string]int // full word → index
	prefixIdx map[string]int // first four letters → index
)

func loadWords() {
	sum := sha256.Sum256([]byte(wordlistFile))
	if hex.EncodeToString(sum[:]) != wordlistSHA256 {
		panic("identity: vendored BIP-39 word list does not match its SHA-256")
	}
	words = strings.Fields(wordlistFile)
	if len(words) != 2048 {
		panic(fmt.Sprintf("identity: word list has %d words", len(words)))
	}
	wordIndex = make(map[string]int, len(words))
	prefixIdx = make(map[string]int, len(words))
	for i, w := range words {
		wordIndex[w] = i
		if len(w) >= 4 {
			prefixIdx[w[:4]] = i
		}
	}
}

// Errors from ParsePhrase.
var (
	ErrPhraseLength = errors.New("identity: a recovery phrase has 24 words")
	ErrUnknownWord  = errors.New("identity: not a recovery-phrase word")
	ErrChecksum     = errors.New("identity: recovery phrase checksum does not match (a word is wrong or out of order)")
)

// EncodePhrase writes a 32-byte seed as 24 words.
func EncodePhrase(seed []byte) ([]string, error) {
	if len(seed) != 32 {
		return nil, fmt.Errorf("identity: seed must be 32 bytes")
	}
	wordsOnce.Do(loadWords)
	sum := sha256.Sum256(seed)
	bits := append(append([]byte(nil), seed...), sum[0]) // 264 bits
	out := make([]string, PhraseWords)
	for i := range out {
		out[i] = words[readBits(bits, i*11, 11)]
	}
	return out, nil
}

// ParsePhrase turns a recovery phrase back into the seed. Words may be
// separated by any whitespace and in any case, and each may be given as its
// first four letters (enough to identify every word in the list).
func ParsePhrase(phrase string) ([]byte, error) {
	wordsOnce.Do(loadWords)
	in := strings.Fields(strings.ToLower(phrase))
	if len(in) != PhraseWords {
		return nil, fmt.Errorf("%w (got %d)", ErrPhraseLength, len(in))
	}
	bits := make([]byte, 33)
	for i, w := range in {
		idx, ok := wordIndex[w]
		if !ok && len(w) == 4 {
			idx, ok = prefixIdx[w]
		}
		if !ok {
			return nil, fmt.Errorf("%w: word %d", ErrUnknownWord, i+1)
		}
		writeBits(bits, i*11, 11, idx)
	}
	seed := bits[:32]
	if sum := sha256.Sum256(seed); sum[0] != bits[32] {
		return nil, ErrChecksum
	}
	return seed, nil
}

// Phrase returns the identity's recovery phrase, words separated by spaces.
func (id *Identity) Phrase() string {
	w, err := EncodePhrase(id.seed[:])
	if err != nil {
		panic(err) // the seed is always 32 bytes
	}
	return strings.Join(w, " ")
}

// FromPhrase rebuilds an identity from its recovery phrase.
func FromPhrase(phrase string) (*Identity, error) {
	seed, err := ParsePhrase(phrase)
	if err != nil {
		return nil, err
	}
	return FromSeed(seed)
}

// readBits returns n bits of b starting at bit offset off (MSB first).
func readBits(b []byte, off, n int) int {
	v := 0
	for i := range n {
		p := off + i
		v = v<<1 | int(b[p/8]>>(7-p%8)&1)
	}
	return v
}

// writeBits stores the low n bits of v into b at bit offset off (MSB first).
func writeBits(b []byte, off, n, v int) {
	for i := range n {
		p := off + i
		if v>>(n-1-i)&1 == 1 {
			b[p/8] |= 1 << (7 - p%8)
		}
	}
}
