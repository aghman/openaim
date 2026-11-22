package rendezvous

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/transport/ip"
)

var update = flag.Bool("update", false, "rewrite spec/vectors/rendezvous_v1.json from the current code")

const vectorsPath = "../../spec/vectors/rendezvous_v1.json"

// Vectors pin the rendezvous derivation and record format
// (spec/dht-records.md). Everything is hex unless noted.
type Vectors struct {
	Comment string `json:"comment"`
	// KDir is Alice's directional key toward Bob, from the identity seeds of
	// spec/vectors/v1.json (it equals k_dir_alice_to_bob there).
	KDir    string         `json:"k_dir"`
	Records []RecordVector `json:"records"`
}

// RecordVector is one record Alice publishes for Bob. The nonce stands in
// for the publisher's randomness.
type RecordVector struct {
	Name      string   `json:"name"`
	Day       uint32   `json:"day"`
	Seq       uint64   `json:"seq"`
	Seed      string   `json:"seed"`
	Pub       string   `json:"ed25519_public"`
	KeyHash   string   `json:"key_hash"`
	Key       string   `json:"dht_key"` // a string
	L         string   `json:"l"`
	PeerID    string   `json:"peer_id"` // base58, as libp2p prints it
	PeerIDHex string   `json:"peer_id_bytes"`
	Addrs     []string `json:"addrs"` // text multiaddrs
	AddrsHex  []string `json:"addrs_bytes"`
	IssuedAt  uint32   `json:"issued_at"`
	ExpiresAt uint32   `json:"expires_at"`
	Locator   string   `json:"locator"`
	Plaintext string   `json:"plaintext"`
	Nonce     string   `json:"nonce"`
	AD        string   `json:"ad"`
	Payload   string   `json:"payload"`
	Value     string   `json:"value"`
}

func buildRendezvousVectors(t *testing.T) Vectors {
	t.Helper()
	ab, _ := newPair(t, 0xA1, 0xB0)
	day := frame.Day(testNow)
	v := Vectors{
		Comment: "OpenAIM rendezvous records, draft v1 (spec/dht-records.md). Not frozen: changes until the end of M2.",
		KDir:    hex.EncodeToString(ab.Send[:]),
	}
	for _, r := range []struct {
		name  string
		day   uint32
		at    time.Time
		nonce byte
	}{
		{"today", day, testNow, 0x4E},
		{"tomorrow, prepublished", day + 1, dayStart(day + 1).Add(-time.Hour + 123*time.Millisecond), 0x4F},
	} {
		k := Derive(ab.Send, r.day)
		l := testLocator(t)
		l.IssuedAt, l.ExpiresAt = r.at, r.at.Add(DefaultTTL)
		seq := uint64(r.at.UnixMilli())
		nonce := bytes.Repeat([]byte{r.nonce}, NonceSize)
		payload, err := SealPayload(k, seq, l, bytes.NewReader(nonce))
		if err != nil {
			t.Fatal(err)
		}
		value, err := ip.SignRendezvousRecord(k.Priv, seq, payload)
		if err != nil {
			t.Fatal(err)
		}
		loc, err := marshalLocator(l)
		if err != nil {
			t.Fatal(err)
		}
		pt, _ := EncodePlaintext(l)
		rv := RecordVector{
			Name: r.name, Day: r.day, Seq: seq,
			Seed: hex.EncodeToString(k.Seed[:]), Pub: hex.EncodeToString(k.Pub),
			KeyHash: hex.EncodeToString(k.KeyHash[:]), Key: k.Key, L: hex.EncodeToString(k.L[:]),
			PeerID: l.ID.String(), PeerIDHex: hex.EncodeToString([]byte(l.ID)),
			IssuedAt: frame.Timestamp(l.IssuedAt), ExpiresAt: frame.Timestamp(l.ExpiresAt),
			Locator: hex.EncodeToString(loc), Plaintext: hex.EncodeToString(pt),
			Nonce: hex.EncodeToString(nonce), AD: hex.EncodeToString(AssociatedData(k, seq)),
			Payload: hex.EncodeToString(payload), Value: hex.EncodeToString(value),
		}
		for _, a := range l.Addrs {
			rv.Addrs = append(rv.Addrs, a.String())
			rv.AddrsHex = append(rv.AddrsHex, hex.EncodeToString(a.Bytes()))
		}
		v.Records = append(v.Records, rv)
	}
	return v
}

func TestRendezvousVectors(t *testing.T) {
	got := buildRendezvousVectors(t)
	b, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	if *update {
		if err := os.WriteFile(vectorsPath, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/rendezvous -run TestRendezvousVectors -update)", err)
	}
	if !bytes.Equal(want, b) {
		t.Fatalf("output differs from %s; if the change is intended, rerun with -update and say so in spec/dht-records.md", vectorsPath)
	}

	// Bob finds and opens the vectors' records.
	_, ba := newPair(t, 0xA1, 0xB0)
	for _, r := range got.Records {
		k := Derive(ba.Recv, r.Day)
		value, _ := hex.DecodeString(r.Value)
		rec, err := ip.ParseRendezvousRecord(r.Key, value)
		if err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		l, err := Open(k, rec)
		if err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		if l.ID.String() != r.PeerID || frame.Timestamp(l.ExpiresAt) != r.ExpiresAt {
			t.Errorf("%s: opened %+v", r.Name, l)
		}
	}
}
