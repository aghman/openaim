package identity

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"strings"
	"testing"
)

// The 256-bit-entropy mnemonics from the BIP-39 reference test vectors
// (trezor/python-mnemonic vectors.json). OpenAIM uses only the mnemonic
// encoding, so only entropy ↔ words is checked here.
var bip39Vectors = []struct{ entropy, words string }{
	{"0000000000000000000000000000000000000000000000000000000000000000",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"},
	{"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
		"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"},
	{"8080808080808080808080808080808080808080808080808080808080808080",
		"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless"},
	{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"},
}

func TestPhraseBIP39Vectors(t *testing.T) {
	for _, v := range bip39Vectors {
		seed, _ := hex.DecodeString(v.entropy)
		w, err := EncodePhrase(seed)
		if err != nil || strings.Join(w, " ") != v.words {
			t.Fatalf("encode %s…: got %q", v.entropy[:8], strings.Join(w, " "))
		}
		got, err := ParsePhrase(v.words)
		if err != nil || !bytes.Equal(got, seed) {
			t.Fatalf("decode %s…: %x, %v", v.entropy[:8], got, err)
		}
	}
}

func TestPhraseRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	for range 500 {
		seed := make([]byte, 32)
		for i := range seed {
			seed[i] = byte(rng.Uint32())
		}
		id, err := FromSeed(seed)
		if err != nil {
			t.Fatal(err)
		}
		back, err := FromPhrase(id.Phrase())
		if err != nil || back.Public() != id.Public() {
			t.Fatalf("round trip: %v", err)
		}
	}
}

func TestPhraseLenientInput(t *testing.T) {
	id := mustID(t, 7)
	w := strings.Fields(id.Phrase())
	var b strings.Builder
	for i, word := range w {
		switch i % 3 {
		case 0:
			b.WriteString(strings.ToUpper(word))
		case 1:
			b.WriteString(word[:min(4, len(word))]) // four-letter prefix
		default:
			b.WriteString(word)
		}
		b.WriteString([]string{" ", "\n", "\t  "}[i%3])
	}
	back, err := FromPhrase(b.String())
	if err != nil || back.Public() != id.Public() {
		t.Fatalf("lenient input: %v", err)
	}
}

func TestPhraseErrors(t *testing.T) {
	good := strings.Fields(mustID(t, 7).Phrase())
	swap := append([]string(nil), good...)
	swap[3], swap[4] = swap[4], swap[3]
	wrong := append([]string(nil), good...)
	wrong[10] = map[bool]string{true: "zoo", false: "abandon"}[wrong[10] != "zoo"]
	for name, c := range map[string]struct {
		phrase string
		want   error
	}{
		"23 words":        {strings.Join(good[:23], " "), ErrPhraseLength},
		"25 words":        {strings.Join(append(good, "zoo"), " "), ErrPhraseLength},
		"unknown word":    {strings.Join(append([]string{"bitcoinz"}, good[1:]...), " "), ErrUnknownWord},
		"3-letter prefix": {strings.Join(append([]string{good[0][:3] + "q"}, good[1:]...), " "), ErrUnknownWord},
		"swapped words":   {strings.Join(swap, " "), ErrChecksum},
		"one wrong word":  {strings.Join(wrong, " "), ErrChecksum},
		"empty":           {"", ErrPhraseLength},
	} {
		if _, err := ParsePhrase(c.phrase); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	if _, err := EncodePhrase(make([]byte, 31)); err == nil {
		t.Error("31-byte seed encoded")
	}
}

// The unknown-word error names the position but never echoes the word, so
// a phrase never ends up in logs through it.
func TestPhraseErrorDoesNotLeakWords(t *testing.T) {
	p := strings.Fields(mustID(t, 7).Phrase())
	p[5] = "notaword"
	_, err := ParsePhrase(strings.Join(p, " "))
	for _, w := range p {
		if strings.Contains(err.Error(), w) {
			t.Fatalf("error %q contains %q", err, w)
		}
	}
}

func FuzzParsePhrase(f *testing.F) {
	f.Add(bip39Vectors[1].words)
	f.Add("zoo zoo")
	f.Fuzz(func(t *testing.T, s string) {
		seed, err := ParsePhrase(s)
		if err != nil {
			return
		}
		w, err := EncodePhrase(seed)
		if err != nil {
			t.Fatal(err)
		}
		again, err := ParsePhrase(strings.Join(w, " "))
		if err != nil || !bytes.Equal(again, seed) {
			t.Fatalf("accepted phrase doesn't round-trip")
		}
	})
}
