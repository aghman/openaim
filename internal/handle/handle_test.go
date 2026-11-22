package handle

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aghman/openaim/internal/identity"
)

func id(t testing.TB, b byte) *identity.Identity {
	t.Helper()
	i, err := identity.FromSeed(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return i
}

var issued = time.Unix(1767225600, 0) // 2026-01-01T00:00:00Z

func mustRecord(t testing.TB, signer *identity.Identity, h, inbox string) *Record {
	t.Helper()
	r, err := NewRecord(signer, h, issued, inbox)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestValidate(t *testing.T) {
	long := func(n int) string { return strings.Repeat("a", n) }
	// Five 48-byte labels: 5*48 + 4 dots = 244 = MaxLen.
	maxName := strings.TrimSuffix(strings.Repeat(long(48)+".", 5), ".")
	if len(maxName) != MaxLen {
		t.Fatalf("test setup: %d", len(maxName))
	}
	good := []string{
		"alice.example.com", "a.co", "skaterdude99.openaim.chat", "a-b.c0.io",
		"0day.example", long(63) + ".com", maxName,
	}
	for _, h := range good {
		if err := Validate(h); err != nil {
			t.Errorf("Validate(%q) = %v", h, err)
		}
	}
	bad := []string{
		"", "com", "localhost",
		"Alice.example.com", "alice.EXAMPLE.com", // uppercase is not canonical
		"xn--80ak6aa92e.com", "alice.xn--p1ai", "XN--80ak6aa92e.com", // punycode
		"-alice.com", "alice-.com", "alice.-com",
		"a..com", ".a.com", "a.com.", // empty labels, trailing dot
		long(64) + ".com", maxName + "a",
		"a_b.com", "a b.com", "a.b/c", "a@b.com", "аlice.com", // last has Cyrillic а
		"10.0.0.1", "127.0.0.1", "a.123",
	}
	for _, h := range bad {
		if err := Validate(h); !errors.Is(err, ErrSyntax) {
			t.Errorf("Validate(%q) = %v, want ErrSyntax", h, err)
		}
	}
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"  @Alice.Example.COM. ": "alice.example.com",
		"bob.example.com":        "bob.example.com",
	} {
		if got, err := Normalize(in); err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "@", "Alİce.com", "XN--80AK6AA92E.COM", "a..com", "alice.com.."} {
		if got, err := Normalize(in); !errors.Is(err, ErrSyntax) {
			t.Errorf("Normalize(%q) = %q, %v; want ErrSyntax", in, got, err)
		}
	}
}

func TestShort(t *testing.T) {
	const reg = "openaim.chat"
	for _, c := range []struct{ h, reg, want string }{
		{"skaterdude99.openaim.chat", reg, "skaterdude99"},
		{"a.b.openaim.chat", reg, "a.b.openaim.chat"}, // only one label deep
		{"openaim.chat", reg, "openaim.chat"},
		{"skaterdude99.notopenaim.chat", reg, "skaterdude99.notopenaim.chat"},
		{"alice.example.com", reg, "alice.example.com"},
		{"skaterdude99.openaim.chat", "", "skaterdude99.openaim.chat"},
		{"skaterdude99.openaim.chat", "Openaim.Chat", "skaterdude99.openaim.chat"},
	} {
		if got := Short(c.h, c.reg); got != c.want {
			t.Errorf("Short(%q, %q) = %q, want %q", c.h, c.reg, got, c.want)
		}
	}
}

// goldenRecord is the record in spec/handle.md §7: seed 32×0x01, handle
// alice.example.com, issued 2026-01-01, inbox hint "/dns/inbox.example.com/tcp/4001".
const goldenRecord = "v=oa1; k=rkeohxlubhyzl7ks3mwtzos5olfgocn7dwkbeg7toseadnapn5oa; t=1767225600; " +
	"i=/dns/inbox.example.com/tcp/4001; " +
	"s=66a2WoIwaGR1g2dqJDRWWm+U/BjxE34HwEEejJpCrv2FqZ6MJGg7wQVBi5dKR7Zv/FbpzlSu3PflYWVP47pdCg=="

func TestGoldenRecord(t *testing.T) {
	r := mustRecord(t, id(t, 1), "alice.example.com", "/dns/inbox.example.com/tcp/4001")
	if got := r.String(); got != goldenRecord {
		t.Fatalf("golden record changed:\n got %s\nwant %s", got, goldenRecord)
	}
	m := ClaimMessage("alice.example.com", r.Key, r.Issued, r.Inbox)
	const want = "11" + "616c6963652e6578616d706c652e636f6d" + // len, handle
		"8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c" + // key
		"000000006955b900" + // issued
		"001f" + "2f646e732f696e626f782e6578616d706c652e636f6d2f7463702f34303031" // len, inbox
	if got := fmt.Sprintf("%x", m); got != want {
		t.Fatalf("claim message %s", got)
	}
}

func TestRecordRoundTrip(t *testing.T) {
	alice := id(t, 1)
	for _, inbox := range []string{"", "/ip4/203.0.113.7/tcp/4001", "/dns/x/" + strings.Repeat("p", 400)} {
		r := mustRecord(t, alice, "alice.example.com", inbox)
		got, err := ParseRecord(r.String())
		if err != nil {
			t.Fatalf("parse %q: %v", r.String(), err)
		}
		if *got != *r {
			t.Fatalf("round trip changed the record")
		}
		if err := got.Verify("alice.example.com"); err != nil {
			t.Fatal(err)
		}
		if got.Key != alice.Public() || !got.IssuedAt().Equal(issued) || got.Inbox != inbox {
			t.Fatalf("fields: %+v", got)
		}
		chunks := r.TXTStrings()
		for _, c := range chunks {
			if len(c) > 255 {
				t.Fatalf("TXT string of %d bytes", len(c))
			}
		}
		if strings.Join(chunks, "") != r.String() || (len(r.String()) > 255) != (len(chunks) > 1) {
			t.Fatalf("TXTStrings split wrongly: %d chunks", len(chunks))
		}
	}
}

func TestRecordSignatureBinding(t *testing.T) {
	alice, mallory := id(t, 1), id(t, 2)
	r := mustRecord(t, alice, "alice.example.com", "/ip4/203.0.113.7/tcp/4001")
	if err := r.Verify("alice.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := r.Verify("alice.example.org"); !errors.Is(err, ErrSignature) {
		t.Fatalf("different handle: %v", err)
	}
	for name, mutate := range map[string]func(*Record){
		"key":    func(r *Record) { r.Key = mallory.Public() },
		"issued": func(r *Record) { r.Issued++ },
		"inbox":  func(r *Record) { r.Inbox = "/ip4/198.51.100.1/tcp/4001" },
		"sig":    func(r *Record) { r.Sig[0] ^= 1 },
	} {
		bad := *r
		mutate(&bad)
		if err := bad.Verify("alice.example.com"); !errors.Is(err, ErrSignature) {
			t.Errorf("changed %s: %v", name, err)
		}
	}
	if _, err := NewRecord(alice, "Alice.example.com", issued, ""); !errors.Is(err, ErrSyntax) {
		t.Fatalf("NewRecord with a bad handle: %v", err)
	}
	if _, err := NewRecord(alice, "alice.example.com", issued, "has space"); !errors.Is(err, ErrRecord) {
		t.Fatalf("NewRecord with a bad inbox: %v", err)
	}
}

func TestClaimMessageUnambiguous(t *testing.T) {
	k := id(t, 1).Public()
	// With plain concatenation of decimal text these would collide:
	// "…" ‖ "12" ‖ "3/x" and "…" ‖ "1" ‖ "23/x".
	pairs := [][2][]byte{
		{ClaimMessage("a.example.com", k, 12, "3/x"), ClaimMessage("a.example.com", k, 1, "23/x")},
		{ClaimMessage("ab.cd", k, 1, ""), ClaimMessage("ab.c", k, 1, "d")},
	}
	for i, p := range pairs {
		if bytes.Equal(p[0], p[1]) {
			t.Errorf("pair %d encodes the same", i)
		}
	}
}

func TestParseRecord(t *testing.T) {
	r := mustRecord(t, id(t, 1), "alice.example.com", "/ip4/203.0.113.7/tcp/4001")
	k, s := r.Key.String(), r.String()[strings.Index(r.String(), "s=")+2:]
	rec := func(fields ...string) string { return strings.Join(fields, "; ") }
	v, kk, tt, ii, ss := "v=oa1", "k="+k, "t=1767225600", "i=/ip4/203.0.113.7/tcp/4001", "s="+s

	accept := []string{
		rec(v, kk, tt, ii, ss),
		rec(v, ss, ii, tt, kk), // any order after v
		"v=oa1;k=" + k + ";t=1767225600;i=/ip4/203.0.113.7/tcp/4001;s=" + s,
		rec(v, kk, tt, ii, ss) + ";",
		"\tv=oa1 ;  " + rec(kk, tt, ii, ss) + " ",
	}
	for _, text := range accept {
		got, err := ParseRecord(text)
		if err != nil || *got != *r {
			t.Errorf("ParseRecord(%q) = %v", text, err)
		}
	}

	upperKey := "k=" + strings.ToUpper(k)
	unpadded := "s=" + strings.TrimRight(s, "=")
	reject := map[string]string{
		"empty":             "",
		"version":           rec("v=oa2", kk, tt, ii, ss),
		"no version":        rec(kk, tt, ii, ss),
		"version not first": rec(kk, v, tt, ii, ss),
		"duplicate k":       rec(v, kk, kk, tt, ii, ss),
		"duplicate i":       rec(v, kk, tt, ii, ii, ss),
		"missing k":         rec(v, tt, ii, ss),
		"missing t":         rec(v, kk, ii, ss),
		"missing s":         rec(v, kk, tt, ii),
		"unknown field":     rec(v, kk, tt, ii, "x=1", ss),
		"empty field":       rec(v, kk, "", tt, ii, ss),
		"two trailing":      rec(v, kk, tt, ii, ss) + ";;",
		"no equals":         rec(v, kk, tt, "i", ss),
		"empty inbox":       rec(v, kk, tt, "i=", ss),
		"uppercase key":     rec(v, upperKey, tt, ii, ss),
		"short key":         rec(v, "k="+k[:51], tt, ii, ss),
		"bad key":           rec(v, "k="+strings.Repeat("a", 52), tt, ii, ss),
		"leading zero t":    rec(v, kk, "t=01767225600", ii, ss),
		"plus t":            rec(v, kk, "t=+1767225600", ii, ss),
		"negative t":        rec(v, kk, "t=-1", ii, ss),
		"huge t":            rec(v, kk, "t=99999999999999999999", ii, ss),
		"unpadded sig":      rec(v, kk, tt, ii, unpadded),
		"short sig":         rec(v, kk, tt, ii, "s=AAAA"),
		"space in value":    rec(v, kk, tt, "i=/ip4/1 /tcp", ss),
		"space before =":    rec(v, "k ="+k, tt, ii, ss),
		"control byte":      rec(v, kk, tt, "i=/ip4/\x00", ss),
		"newline":           rec(v, kk, tt, ii, ss) + "\n",
		"non-ascii":         rec(v, kk, tt, "i=/dns/é", ss),
		"oversize":          rec(v, kk, tt, "i="+strings.Repeat("a", MaxRecordLen), ss),
		"oversize inbox":    rec(v, kk, tt, "i="+strings.Repeat("a", MaxInboxLen+1), ss),
	}
	for name, text := range reject {
		if _, err := ParseRecord(text); !errors.Is(err, ErrRecord) {
			t.Errorf("%s: ParseRecord(%q) = %v, want ErrRecord", name, text, err)
		}
	}
}

func TestIsCandidate(t *testing.T) {
	for text, want := range map[string]bool{
		"v=oa1; k=x": true, "v=oa1;k=x": true, "v=oa1": true, "v=oa1 ;": true,
		"v=oa10; k=x": false, "v=oa2; k=x": false, "google-site-verification=x": false, " v=oa1": false,
	} {
		if got := isCandidate(text); got != want {
			t.Errorf("isCandidate(%q) = %v", text, got)
		}
	}
}

func TestComparePin(t *testing.T) {
	alice, bob := id(t, 1).Public(), id(t, 2).Public()
	res := &Result{Key: alice}
	for _, c := range []struct {
		res  *Result
		err  error
		want PinStatus
	}{
		{res, nil, PinVerified},
		{&Result{Key: bob}, nil, PinMoved},
		{nil, fmt.Errorf("x: %w", ErrNotFound), PinUnverified},
		{nil, ErrSignature, PinUnverified},
		{nil, ErrRecord, PinUnverified},
		{nil, ErrAmbiguous, PinUnverified},
		{nil, ErrRedirect, PinUnverified},
		{nil, ErrForbiddenAddr, PinUnverified},
		{nil, ErrTooLarge, PinUnverified},
		{nil, fmt.Errorf("%w: timeout", ErrUnreachable), PinUnreachable},
		{nil, ErrDisagree, PinUnreachable},
		{nil, ErrConfig, PinUnreachable},
	} {
		got := ComparePin(c.res, c.err, alice)
		if got.Status != c.want {
			t.Errorf("ComparePin(%v, %v) = %v, want %v", c.res, c.err, got.Status, c.want)
		}
		if (got.Result != nil) != (c.want == PinVerified || c.want == PinMoved) || (got.Err != nil) != (got.Result == nil) {
			t.Errorf("ComparePin(%v): result %v, err %v", c.err, got.Result, got.Err)
		}
	}
}

func TestNextCheck(t *testing.T) {
	last := issued
	day := 24 * time.Hour
	for _, c := range []struct {
		s    PinStatus
		u    float64
		want time.Duration
	}{
		{PinVerified, 0, 26 * day},
		{PinVerified, 0.5, 30 * day},
		{PinVerified, 1, 34 * day},
		{PinVerified, -3, 26 * day}, // clamped
		{PinVerified, 7, 34 * day},
		{PinMoved, 0.5, day},
		{PinUnverified, 0, day - 4*time.Hour},
		{PinUnreachable, 1, day + 4*time.Hour},
	} {
		if got := NextCheck(last, c.s, c.u).Sub(last); got != c.want {
			t.Errorf("NextCheck(%v, %v) = +%v, want +%v", c.s, c.u, got, c.want)
		}
	}
	for range 100 {
		d := NextCheckRandom(last, PinVerified).Sub(last)
		if d < 26*day || d > 34*day {
			t.Fatalf("NextCheckRandom = +%v", d)
		}
	}
}

func FuzzParseRecord(f *testing.F) {
	r := mustRecord(f, id(f, 1), "alice.example.com", "/ip4/203.0.113.7/tcp/4001")
	f.Add(r.String())
	f.Add(mustRecord(f, id(f, 2), "b.co", "").String())
	f.Add("v=oa1; k=; t=; s=")
	f.Add("v=oa1;;;")
	f.Fuzz(func(t *testing.T, text string) {
		r, err := ParseRecord(text)
		if err != nil {
			if !errors.Is(err, ErrRecord) {
				t.Fatalf("error without ErrRecord: %v", err)
			}
			return
		}
		// Whatever parses has one canonical form, which parses back to it.
		again, err := ParseRecord(r.String())
		if err != nil || *again != *r {
			t.Fatalf("canonical form %q does not round-trip: %v", r.String(), err)
		}
		_ = r.Verify("alice.example.com")
	})
}
