package frame

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aghman/openaim/internal/identity"
)

var update = flag.Bool("update", false, "rewrite spec/vectors/*.json from the current code")

const vectorsPath = "../../spec/vectors/v1.json"

// Vectors are the published golden test vectors (design §10.4). Everything
// is hex unless noted. They pin spec/wire.md: any change to a label, layout
// or derivation changes them.
type Vectors struct {
	Comment string `json:"comment"`

	AliceSeed string `json:"alice_seed"`
	BobSeed   string `json:"bob_seed"`
	AliceEd   string `json:"alice_ed25519"`
	BobEd     string `json:"bob_ed25519"`
	AliceX    string `json:"alice_x25519"`
	BobX      string `json:"bob_x25519"`
	AliceB32  string `json:"alice_key_b32"`
	AliceID   string `json:"alice_key_id"`
	Safety    string `json:"safety_number"`
	ClaimSig  string `json:"alice_sig_handle_claim"` // Sign("openaim/v1/handle-claim", "example")

	KDirAB string `json:"k_dir_alice_to_bob"`
	KDirBA string `json:"k_dir_bob_to_alice"`
	KSivAB string `json:"k_siv_alice_to_bob"`

	Day     uint32 `json:"day"` // days since 2025-01-01
	ConvTag string `json:"conv_tag_alice_to_bob"`

	Messages []MessageVector `json:"messages"`
}

// MessageVector is one message Alice seals to Bob.
type MessageVector struct {
	Name    string   `json:"name"`
	Layout  string   `json:"layout"`
	Type    uint8    `json:"content_type"`
	Flags   uint8    `json:"flags"`
	Time    uint32   `json:"timestamp"`
	Seq     uint64   `json:"seq"`
	BodyStr string   `json:"body_utf8"`
	Inner   string   `json:"inner"`
	MsgID   string   `json:"msg_id"`
	KMsg    string   `json:"k_msg"`
	Frames  []string `json:"frames"`
}

func buildVectors(t *testing.T) Vectors {
	t.Helper()
	aseed, bseed := bytes.Repeat([]byte{0xA1}, 32), bytes.Repeat([]byte{0xB0}, 32)
	alice, err := identity.FromSeed(aseed)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := identity.FromSeed(bseed)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := alice.Pair(bob.Public())
	if err != nil {
		t.Fatal(err)
	}
	ax, _ := alice.Public().X25519()
	bx, _ := bob.Public().X25519()
	ap, bp := alice.Public(), bob.Public()

	k := NewConvKey(pair.Send)
	kba := pair.Recv
	at := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	day := Day(at)
	tag := k.Tag(day)

	v := Vectors{
		Comment:   "OpenAIM wire draft v1 golden vectors (spec/wire.md). Not frozen: changes until the end of M2.",
		AliceSeed: hex.EncodeToString(aseed), BobSeed: hex.EncodeToString(bseed),
		AliceEd: hex.EncodeToString(ap[:]), BobEd: hex.EncodeToString(bp[:]),
		AliceX: hex.EncodeToString(ax.Bytes()), BobX: hex.EncodeToString(bx.Bytes()),
		AliceB32: ap.String(), AliceID: ap.KeyID(),
		Safety:   identity.SafetyNumber(ap, bp),
		ClaimSig: hex.EncodeToString(alice.Sign("openaim/v1/handle-claim", []byte("example"))),
		KDirAB:   hex.EncodeToString(pair.Send[:]), KDirBA: hex.EncodeToString(kba[:]),
		KSivAB: hex.EncodeToString(k.SIV[:]),
		Day:    day, ConvTag: hex.EncodeToString(tag[:]),
	}
	for _, m := range []struct {
		name   string
		layout Layout
		in     Inner
	}{
		{"single-fragment IM", LayoutMesh, Inner{Type: IM, Time: Timestamp(at), Seq: 1, Body: []byte("hey, you there?")}},
		{"three-fragment IM", LayoutMesh, Inner{Type: IM, Flags: FlagAckRequested, Time: Timestamp(at) + 5, Seq: 2,
			Body: bytes.Repeat([]byte("all work and no play makes jack a dull boy. "), 8)}},
		{"IP-layout IM", LayoutIP, Inner{Type: IM, Time: Timestamp(at) + 9, Seq: 300, Body: []byte("long messages use the IP layout")}},
	} {
		inner := m.in.Marshal()
		s, err := Seal(k, tag, m.layout, inner)
		if err != nil {
			t.Fatal(err)
		}
		mv := MessageVector{
			Name: m.name, Layout: m.layout.String(),
			Type: uint8(m.in.Type), Flags: uint8(m.in.Flags), Time: m.in.Time, Seq: m.in.Seq, BodyStr: string(m.in.Body),
			Inner: hex.EncodeToString(inner), MsgID: hex.EncodeToString(s.MsgID[:]),
			KMsg: hex.EncodeToString(k.msgKey(tag, s.MsgID, len(s.Frames), m.layout)),
		}
		for _, f := range s.Frames {
			mv.Frames = append(mv.Frames, hex.EncodeToString(f))
		}
		v.Messages = append(v.Messages, mv)
	}
	return v
}

func TestGoldenVectors(t *testing.T) {
	got := buildVectors(t)
	b, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	if *update {
		if err := os.MkdirAll(filepath.Dir(vectorsPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorsPath, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/frame -run TestGoldenVectors -update)", err)
	}
	if !bytes.Equal(want, b) {
		t.Fatalf("output differs from %s; if the wire format change is intended, rerun with -update and say so in spec/wire.md", vectorsPath)
	}

	// The vectors must also open: Bob receives Alice's frames.
	var v Vectors
	if err := json.Unmarshal(want, &v); err != nil {
		t.Fatal(err)
	}
	bobSeed, _ := hex.DecodeString(v.BobSeed)
	bob, _ := identity.FromSeed(bobSeed)
	aliceKey, _ := hex.DecodeString(v.AliceEd)
	ak, _ := identity.ParsePublicKey(aliceKey)
	pair, err := bob.Pair(ak)
	if err != nil {
		t.Fatal(err)
	}
	k := NewConvKey(pair.Recv)
	r := &Receiver{Keys: keyring{k.Tag(v.Day): {{Key: k, ID: "alice"}}}, Dedup: &MemDedup{},
		Now: func() time.Time { return TimeOf(v.Messages[0].Time) }}
	for _, m := range v.Messages {
		var res Result
		for _, fh := range m.Frames {
			f, _ := hex.DecodeString(fh)
			if res, err = r.Accept(f); err != nil {
				t.Fatalf("%s: %v", m.Name, err)
			}
		}
		if res.Status != Delivered || string(res.Message.Inner.Body) != m.BodyStr {
			t.Fatalf("%s: status %v", m.Name, res.Status)
		}
	}
}
