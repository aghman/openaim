package frame

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
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
	AlicePhr  string `json:"alice_recovery_phrase"`
	Safety    string `json:"safety_number"`
	ClaimSig  string `json:"alice_sig_handle_claim"` // Sign("openaim/v1/handle-claim", "example")

	KDirAB string `json:"k_dir_alice_to_bob"`
	KDirBA string `json:"k_dir_bob_to_alice"`
	KSivAB string `json:"k_siv_alice_to_bob"`

	Day     uint32 `json:"day"` // days since 2025-01-01
	ConvTag string `json:"conv_tag_alice_to_bob"`

	Messages []MessageVector `json:"messages"`

	FirstContacts []FirstContactVector `json:"first_contacts"`

	Rotation RotationVector `json:"rotation"`
}

// RotationVector is a key-rotation statement (spec/wire.md §4.6): Alice's
// recovery key moves her from alice_ed25519 to a new identity key.
type RotationVector struct {
	RecoverySeed  string `json:"recovery_seed"`
	RecoveryEd    string `json:"recovery_ed25519"`
	NewSeed       string `json:"new_seed"`
	OldEd         string `json:"old_ed25519"`
	NewEd         string `json:"new_ed25519"`
	IssuedAt      uint32 `json:"issued_at"` // seconds since 2025-01-01
	SignedMessage string `json:"signed_message"`
	Signature     string `json:"signature"`
	Body          string `json:"rotate_body"` // the ROTATE protobuf body, content type 14
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

// FirstContactVector is one first contact Alice seals to Bob (spec/wire.md
// §11). The ephemeral seed stands in for the sender's randomness.
type FirstContactVector struct {
	Name     string   `json:"name"`
	Layout   string   `json:"layout"`
	ESeed    string   `json:"ephemeral_seed"`
	E        string   `json:"e"`
	ES       string   `json:"es"`
	SS       string   `json:"ss"`
	HR       string   `json:"h_r"`
	CK1      string   `json:"ck1"`
	CK2      string   `json:"ck2"`
	KSiv     string   `json:"k_siv"`
	Type     uint8    `json:"content_type"`
	Time     uint32   `json:"timestamp"`
	Inner    string   `json:"inner"`
	MsgID    string   `json:"msg_id"`
	KS       string   `json:"k_s"`
	KPayload string   `json:"k_payload"`
	KTail    string   `json:"k_tail,omitempty"`
	DedupTag string   `json:"dedup_tag"`
	Frames   []string `json:"frames"`
}

// rotateBody hand-encodes a ROTATE body (old_key = 1, new_key = 2,
// issued_at = 3, signature = 4) in field order, as deterministic protobuf
// does, since internal/frame doesn't import internal/body.
func rotateBody(st identity.RotationStatement, sig []byte) []byte {
	b := append([]byte{1<<3 | 2, 32}, st.Old[:]...)
	b = append(append(b, 2<<3|2, 32), st.New[:]...)
	b = binary.AppendUvarint(append(b, 3<<3|0), uint64(st.IssuedAt))
	return append(append(b, 4<<3|2, byte(len(sig))), sig...)
}

func buildRotation(t *testing.T, old identity.PublicKey, at time.Time) RotationVector {
	t.Helper()
	rseed, nseed := bytes.Repeat([]byte{0xAC}, 32), bytes.Repeat([]byte{0xA2}, 32)
	rec, err := identity.FromSeed(rseed)
	if err != nil {
		t.Fatal(err)
	}
	nw, err := identity.FromSeed(nseed)
	if err != nil {
		t.Fatal(err)
	}
	st := identity.RotationStatement{Old: old, New: nw.Public(), IssuedAt: Timestamp(at) + 60}
	sig, err := identity.SignRotation(rec, st)
	if err != nil {
		t.Fatal(err)
	}
	rp, np := rec.Public(), nw.Public()
	return RotationVector{
		RecoverySeed: hex.EncodeToString(rseed), RecoveryEd: hex.EncodeToString(rp[:]),
		NewSeed: hex.EncodeToString(nseed), OldEd: hex.EncodeToString(old[:]), NewEd: hex.EncodeToString(np[:]),
		IssuedAt: st.IssuedAt, SignedMessage: hex.EncodeToString(st.SignedMessage()),
		Signature: hex.EncodeToString(sig), Body: hex.EncodeToString(rotateBody(st, sig)),
	}
}

// buddyRequest hand-encodes a BUDDY_REQUEST body (display_name = 1,
// greeting = 2), since internal/frame doesn't import internal/body.
// Strings must be under 128 bytes.
func buddyRequest(name, greeting string) []byte {
	b := append([]byte{1<<3 | 2, byte(len(name))}, name...)
	return append(append(b, 2<<3|2, byte(len(greeting))), greeting...)
}

func buildFirstContacts(t *testing.T, alice *identity.Identity, bob identity.PublicKey, at time.Time) []FirstContactVector {
	t.Helper()
	bx, _ := bob.X25519()
	var out []FirstContactVector
	for _, c := range []struct {
		name   string
		layout Layout
		eb     byte
		body   []byte
	}{
		{"one-fragment mesh request", LayoutMesh, 0xE1, buddyRequest("Alice", "hi bob, it's alice from the meetup")},
		{"two-fragment mesh request", LayoutMesh, 0xE2, buddyRequest("Alice",
			"hi bob! it's alice, we met at the radio club on saturday. you said to add you here, so here I am. talk soon?")},
		{"IP-layout request", LayoutIP, 0xE3, buddyRequest("Alice", "hello over IP")},
	} {
		in := Inner{Type: BuddyRequest, Time: Timestamp(at) + 20, Body: c.body}
		inner := in.Marshal()
		eSeed := bytes.Repeat([]byte{c.eb}, 32)
		s, err := SealFirstContact(alice, bob, c.layout, inner, bytes.NewReader(eSeed))
		if err != nil {
			t.Fatal(err)
		}
		ePriv, _ := ecdh.X25519().NewPrivateKey(eSeed)
		es, _ := ePriv.ECDH(bx)
		ss, _ := alice.DH(bx)
		hR := sha256.Sum256(append([]byte(labelFC), bob[:]...))
		ck1 := fcCK1(bob, s.E[:], es)
		ck2 := fcCK2(ck1, ss, alice.Public())
		n := len(s.Frames)
		dt := fcDedupTag(s.E)
		v := FirstContactVector{
			Name: c.name, Layout: c.layout.String(), ESeed: hex.EncodeToString(eSeed), E: hex.EncodeToString(s.E[:]),
			ES: hex.EncodeToString(es), SS: hex.EncodeToString(ss), HR: hex.EncodeToString(hR[:]),
			CK1: hex.EncodeToString(ck1), CK2: hex.EncodeToString(ck2), KSiv: hex.EncodeToString(fcSIV(ck2)),
			Type: uint8(in.Type), Time: in.Time, Inner: hex.EncodeToString(inner), MsgID: hex.EncodeToString(s.MsgID[:]),
			KS:       hex.EncodeToString(fcKey(ck1, labelFCEncS, s.MsgID, n, c.layout)),
			KPayload: hex.EncodeToString(fcKey(ck2, labelFCPayload, s.MsgID, n, c.layout)),
			DedupTag: hex.EncodeToString(dt[:]),
		}
		if n > 1 {
			v.KTail = hex.EncodeToString(fcKey(ck1, labelFCTail, s.MsgID, n, c.layout))
		}
		for _, f := range s.Frames {
			v.Frames = append(v.Frames, hex.EncodeToString(f))
		}
		out = append(out, v)
	}
	return out
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
		AliceB32: ap.String(), AliceID: ap.KeyID(), AlicePhr: alice.Phrase(),
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
	v.FirstContacts = buildFirstContacts(t, alice, bp, at)
	v.Rotation = buildRotation(t, ap, at)
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

	// Bob accepts Alice's rotation under her pinned recovery key, and no other.
	rv := v.Rotation
	var st identity.RotationStatement
	for _, f := range []struct {
		dst *identity.PublicKey
		hex string
	}{{&st.Old, rv.OldEd}, {&st.New, rv.NewEd}} {
		b, _ := hex.DecodeString(f.hex)
		if *f.dst, err = identity.ParsePublicKey(b); err != nil {
			t.Fatal(err)
		}
	}
	st.IssuedAt = rv.IssuedAt
	rb, _ := hex.DecodeString(rv.RecoveryEd)
	rk, _ := identity.ParsePublicKey(rb)
	sig, _ := hex.DecodeString(rv.Signature)
	if st.Old != ak || hex.EncodeToString(st.SignedMessage()) != rv.SignedMessage {
		t.Fatal("rotation: statement doesn't match its signed message")
	}
	if err := identity.VerifyRotation(rk, st, sig); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	if err := identity.VerifyRotation(ak, st, sig); err == nil {
		t.Fatal("rotation verified under the old identity key")
	}

	// Bob opens Alice's first contacts, last fragment first.
	for _, fc := range v.FirstContacts {
		fr := &FirstContactReceiver{Me: bob, Dedup: &MemDedup{}, Now: func() time.Time { return TimeOf(fc.Time) }}
		var res FirstContactResult
		for i := len(fc.Frames) - 1; i >= 0; i-- {
			f, _ := hex.DecodeString(fc.Frames[i])
			if res, err = fr.Accept(f); err != nil {
				t.Fatalf("%s: %v", fc.Name, err)
			}
		}
		inner, _ := hex.DecodeString(fc.Inner)
		if res.Status != Delivered || res.Message.Sender != ak || !bytes.Equal(res.Message.Inner.Marshal(), inner) {
			t.Fatalf("%s: status %v", fc.Name, res.Status)
		}
	}
}
