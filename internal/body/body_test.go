package body

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/identity"
	pb "github.com/aghman/openaim/internal/wirepb"
)

func idKey(t testing.TB, b byte) []byte {
	t.Helper()
	id, err := identity.FromSeed(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	k := id.Public()
	return k[:]
}

// realisticReach is a REACH with one IP hint (an Ed25519 peer ID is 38
// bytes) carrying an IPv4 and an IPv6 QUIC address, plus a mesh node.
func realisticReach(t testing.TB) *pb.Reach {
	t.Helper()
	v4 := append([]byte{0x04, 203, 0, 113, 7, 0x91, 0x02, 0x0f, 0xa1}, 0xcc, 0x03) // /ip4/…/udp/4001/quic-v1
	v6 := append(append([]byte{0x29}, bytes.Repeat([]byte{0x20}, 16)...), 0x91, 0x02, 0x0f, 0xa1, 0xcc, 0x03)
	return &pb.Reach{
		Seq: 7, IssuedAt: 1000, ExpiresAt: 1000 + 86400,
		Ip:   []*pb.IPHint{{PeerId: bytes.Repeat([]byte{0x12}, 38), Addrs: [][]byte{v4, v6}}},
		Mesh: &pb.MeshHint{NodeNum: 0x0a0b0c0d},
	}
}

func examples(t testing.TB) []proto.Message {
	return []proto.Message{
		&pb.Ack{Entries: []*pb.AckEntry{{MsgId: bytes.Repeat([]byte{1}, 8), Have: 0b111}}},
		&pb.Presence{State: pb.PresenceState_PRESENCE_STATE_AWAY, IdleMinutes: 12, AwayRev: 3, MyMeshNode: 0x0a0b0c0d},
		&pb.ProfileReq{Profile: true},
		&pb.Profile{DisplayName: "SkaterDude99", Text: "brb, skating\nback at 5"},
		&pb.AwayMsg{Text: "I'm not here right now", Rev: 3},
		&pb.Typing{State: pb.TypingState_TYPING_STATE_TYPING},
		&pb.BuddyAccept{PresenceKey: bytes.Repeat([]byte{9}, 32), RecoveryKey: idKey(t, 2), DisplayName: "Jen",
			Reach: realisticReach(t), Caps: &pb.Caps{WireVersion: 1, Features: uint64(pb.Feature_FEATURE_TYPING | pb.Feature_FEATURE_IP_LAYOUT)}},
		realisticReach(t),
		&pb.Caps{WireVersion: 1, UserAgent: "openaim/0.1"},
		&pb.Rotate{OldKey: idKey(t, 1), NewKey: idKey(t, 2), IssuedAt: 5, Signature: make([]byte, 64)},
		&pb.BuddyRequest{DisplayName: "SkaterDude99", Greeting: "hey, it's jen from the meetup!", Reach: meshReach(),
			RecoveryKey: idKey(t, 3), Caps: &pb.Caps{WireVersion: 1}},
	}
}

// meshReach is a REACH with only a mesh node, as a mesh-only requester
// sends, issued in late 2026 and valid for the 14-day window.
func meshReach() *pb.Reach {
	const issued = 59_918_400
	return &pb.Reach{Seq: 1, IssuedAt: issued, ExpiresAt: issued + 14*86400, Mesh: &pb.MeshHint{NodeNum: 0x0a0b0c0d}}
}

func TestRoundTrip(t *testing.T) {
	seen := map[frame.ContentType]bool{}
	for _, m := range examples(t) {
		ct, b, err := Marshal(m)
		if err != nil {
			t.Fatalf("%T: %v", m, err)
		}
		seen[ct] = true
		got, err := Unmarshal(ct, b)
		if err != nil {
			t.Fatalf("%T: unmarshal: %v", m, err)
		}
		if !proto.Equal(got, m) {
			t.Fatalf("%T: round trip changed the message", m)
		}
		// Deterministic: marshalling again gives the same bytes.
		if _, b2, _ := Marshal(got); !bytes.Equal(b, b2) {
			t.Fatalf("%T: encoding not deterministic", m)
		}
	}
	if len(seen) != len(contentTypes) {
		t.Fatalf("examples cover %d of %d content types", len(seen), len(contentTypes))
	}
	if _, err := Unmarshal(frame.IM, []byte("hi")); err == nil {
		t.Error("IM has no protobuf body")
	}
	if _, err := Unmarshal(frame.Presence, []byte{0xff}); !errors.Is(err, ErrInvalid) {
		t.Errorf("garbage presence: %v", err)
	}
}

// TestMeshBudgets checks that the bodies the design sends on mesh fit their
// byte budgets (spec/wire.md §5.1, §6): a one-fragment mesh message has 159 B
// of body and a four-fragment one 657 B.
func TestMeshBudgets(t *testing.T) {
	const oneFrag, fourFrags = 159, 657
	size := func(m proto.Message) int {
		_, b, err := Marshal(m)
		if err != nil {
			t.Fatalf("%T: %v", m, err)
		}
		return len(b)
	}
	full := &pb.Ack{}
	for i := range MaxAckEntries {
		full.Entries = append(full.Entries, &pb.AckEntry{MsgId: bytes.Repeat([]byte{byte(i)}, 8), Have: 0xFFFF})
	}
	for _, c := range []struct {
		name  string
		m     proto.Message
		limit int
	}{
		{"presence", &pb.Presence{State: pb.PresenceState_PRESENCE_STATE_AWAY, IdleMinutes: 600, AwayRev: 1 << 20, MyMeshNode: 0xFFFFFFFF}, 16},
		{"ack, 1 entry", &pb.Ack{Entries: []*pb.AckEntry{{MsgId: make([]byte, 8), Have: 0xF}}}, 16},
		{"ack, 8 entries", &pb.Ack{Entries: full.Entries[:8]}, oneFrag},
		{"ack, 32 entries", full, fourFrags},
		{"reach", realisticReach(t), oneFrag},
		{"buddy accept", examples(t)[6], oneFrag + 166},
		{"caps", &pb.Caps{WireVersion: 1, Features: 0xF}, 8},
		{"rotate", examples(t)[9], oneFrag},
	} {
		if n := size(c.m); n > c.limit {
			t.Errorf("%s: %d bytes, budget %d", c.name, n, c.limit)
		} else {
			t.Logf("%-16s %3d B (budget %d)", c.name, n, c.limit)
		}
	}
}

func TestValidation(t *testing.T) {
	key := idKey(t, 1)
	for name, m := range map[string]proto.Message{
		"empty ack":           &pb.Ack{},
		"short msg_id":        &pb.Ack{Entries: []*pb.AckEntry{{MsgId: make([]byte, 7), Have: 1}}},
		"zero bitmap":         &pb.Ack{Entries: []*pb.AckEntry{{MsgId: make([]byte, 8)}}},
		"17-bit bitmap":       &pb.Ack{Entries: []*pb.AckEntry{{MsgId: make([]byte, 8), Have: 1 << 16}}},
		"no presence state":   &pb.Presence{},
		"bad presence state":  &pb.Presence{State: 9},
		"idle forever":        &pb.Presence{State: 1, IdleMinutes: MaxIdleMinutes + 1},
		"empty profile req":   &pb.ProfileReq{},
		"long display name":   &pb.Profile{DisplayName: strings.Repeat("x", 65)},
		"escape in name":      &pb.Profile{DisplayName: "evil\x1b[2J"},
		"C1 in away msg":      &pb.AwayMsg{Text: "a\u009bb"},
		"long away msg":       &pb.AwayMsg{Text: strings.Repeat("x", MaxText+1)},
		"no typing state":     &pb.Typing{},
		"short presence key":  &pb.BuddyAccept{PresenceKey: make([]byte, 31)},
		"bad recovery key":    &pb.BuddyAccept{PresenceKey: make([]byte, 32), RecoveryKey: append([]byte{1}, make([]byte, 31)...)},
		"accept, bad reach":   &pb.BuddyAccept{PresenceKey: make([]byte, 32), Reach: &pb.Reach{}},
		"reach expired":       &pb.Reach{IssuedAt: 5, ExpiresAt: 5},
		"reach, 5 IP hints":   &pb.Reach{ExpiresAt: 1, Ip: make([]*pb.IPHint, 5)},
		"reach, no peer id":   &pb.Reach{ExpiresAt: 1, Ip: []*pb.IPHint{{}}},
		"reach, huge addr":    &pb.Reach{ExpiresAt: 1, Ip: []*pb.IPHint{{PeerId: []byte{1}, Addrs: [][]byte{make([]byte, 129)}}}},
		"reach, bad gateway":  &pb.Reach{ExpiresAt: 1, Gateway: []*pb.GatewayHint{{GatewayKey: make([]byte, 32)}}},
		"reach, bad mailbox":  &pb.Reach{ExpiresAt: 1, Mailbox: []*pb.MailboxHint{{MailboxKey: make([]byte, 32), DepositToken: make([]byte, 32)}}},
		"caps, no version":    &pb.Caps{},
		"rotate to same key":  &pb.Rotate{OldKey: key, NewKey: key, Signature: make([]byte, 64)},
		"rotate, short sig":   &pb.Rotate{OldKey: key, NewKey: idKey(t, 2), Signature: make([]byte, 63)},
		"rotate, bad new key": &pb.Rotate{OldKey: key, NewKey: make([]byte, 32), Signature: make([]byte, 64)},
		"request, long name":  &pb.BuddyRequest{DisplayName: strings.Repeat("x", MaxDisplayName+1)},
		"request, long greet": &pb.BuddyRequest{Greeting: strings.Repeat("x", MaxGreeting+1)},
		"request, CSI greet":  &pb.BuddyRequest{Greeting: "hi\u009b2J"},
		"request, bad rk":     &pb.BuddyRequest{RecoveryKey: make([]byte, 31)},
		"request, bad reach":  &pb.BuddyRequest{Reach: &pb.Reach{}},
		"request, bad caps":   &pb.BuddyRequest{Caps: &pb.Caps{}},
	} {
		if _, _, err := Marshal(m); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Marshal err = %v, want ErrInvalid", name, err)
		}
		// The same bytes arriving from the wire are rejected too.
		ct, _ := ContentTypeOf(m)
		b, _ := proto.Marshal(m)
		if _, err := Unmarshal(ct, b); err == nil {
			t.Errorf("%s: Unmarshal accepted it", name)
		}
	}
}

// TestFirstContactBudgets checks that buddy requests fit FIRST_CONTACT
// frames (spec/wire.md §11.1, §11.6): 87 B of body in one mesh fragment,
// 229 B in two, 3983 B in one IP fragment.
func TestFirstContactBudgets(t *testing.T) {
	hdr := len(frame.Inner{Type: frame.BuddyRequest}.Marshal())
	oneFrag := frame.FirstContactCapacity(frame.LayoutMesh, 0) - hdr
	twoFrags := frame.FirstContactMaxInner(frame.LayoutMesh) - hdr
	ip := frame.FirstContactMaxInner(frame.LayoutIP) - hdr
	if oneFrag != 87 || twoFrags != 229 || ip != 3983 {
		t.Fatalf("budgets %d / %d / %d", oneFrag, twoFrags, ip)
	}
	manyHints := realisticReach(t)
	for range 3 {
		manyHints.Ip = append(manyHints.Ip, manyHints.Ip[0])
	}
	for _, c := range []struct {
		name  string
		m     *pb.BuddyRequest
		limit int
	}{
		{"mesh, typical", &pb.BuddyRequest{DisplayName: "SkaterDude99", Greeting: "hey, it's jen from the meetup!", Reach: meshReach()}, oneFrag},
		{"mesh, long greeting", &pb.BuddyRequest{DisplayName: "SkaterDude99", Greeting: strings.Repeat("g", 140), Reach: meshReach()}, twoFrags},
		{"mesh, max name", &pb.BuddyRequest{DisplayName: strings.Repeat("n", MaxDisplayName), Greeting: strings.Repeat("g", 120), Reach: meshReach()}, twoFrags},
		{"IP, with recovery key", &pb.BuddyRequest{DisplayName: "SkaterDude99", Greeting: strings.Repeat("g", 60), Reach: realisticReach(t),
			RecoveryKey: idKey(t, 3), Caps: &pb.Caps{WireVersion: 1, Features: 0xF}}, twoFrags},
		{"IP, everything", &pb.BuddyRequest{DisplayName: strings.Repeat("n", MaxDisplayName), Greeting: strings.Repeat("g", MaxGreeting),
			Reach: manyHints, RecoveryKey: idKey(t, 3), Caps: &pb.Caps{WireVersion: 1, Features: 0xF, UserAgent: strings.Repeat("u", MaxUserAgent)}}, ip},
	} {
		_, b, err := Marshal(c.m)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(b) > c.limit {
			t.Errorf("%s: %d bytes, budget %d", c.name, len(b), c.limit)
		} else {
			t.Logf("%-22s %4d B (budget %d)", c.name, len(b), c.limit)
		}
	}
}

// The golden first-contact vectors carry valid BUDDY_REQUEST bodies.
func TestFirstContactVectorBodies(t *testing.T) {
	raw, err := os.ReadFile("../../spec/vectors/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		FirstContacts []struct {
			Name  string `json:"name"`
			Inner string `json:"inner"`
		} `json:"first_contacts"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.FirstContacts) == 0 {
		t.Fatal("no first-contact vectors")
	}
	for _, fc := range v.FirstContacts {
		b, _ := hex.DecodeString(fc.Inner)
		in, err := frame.ParseInner(b)
		if err != nil || in.Type != frame.BuddyRequest {
			t.Fatalf("%s: inner %v, type %v", fc.Name, err, in.Type)
		}
		if _, err := Unmarshal(in.Type, in.Body); err != nil {
			t.Errorf("%s: %v", fc.Name, err)
		}
	}
}

func TestIMText(t *testing.T) {
	if s, err := IMText([]byte("hey 👋\nwhat's up?\t:)")); err != nil || !strings.HasPrefix(s, "hey") {
		t.Fatalf("valid IM: %v", err)
	}
	for name, b := range map[string][]byte{
		"empty": nil, "bad UTF-8": {0xff, 0xfe}, "escape": []byte("\x1b]0;pwned\x07"), "NUL": []byte("a\x00b"), "C1 CSI": []byte("a\u009b2J"),
	} {
		if _, err := IMText(b); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// FuzzUnmarshal: arbitrary bytes under every content type never panic, and
// anything accepted re-encodes to a body that is accepted again and equal.
func FuzzUnmarshal(f *testing.F) {
	for _, m := range examples(f) {
		ct, b, _ := Marshal(m)
		f.Add(uint8(ct), b)
	}
	f.Fuzz(func(t *testing.T, ct uint8, b []byte) {
		m, err := Unmarshal(frame.ContentType(ct), b)
		if err != nil {
			return
		}
		ct2, b2, err := Marshal(m)
		if err != nil || ct2 != frame.ContentType(ct) {
			t.Fatalf("accepted body fails to re-encode: %v", err)
		}
		m2, err := Unmarshal(ct2, b2)
		if err != nil || !proto.Equal(m, m2) {
			t.Fatalf("re-encoded body differs: %v", err)
		}
	})
}
