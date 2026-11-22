package handle

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aghman/openaim/internal/identity"
)

// LabelClaim is the signature label for handle claims (design §10.2).
const LabelClaim = "openaim/v1/handle-claim"

// Version is the only record version this package understands.
const Version = "oa1"

// Record limits (spec/handle.md §2).
const (
	MaxRecordLen = 1024 // the whole record text, after joining TXT strings
	MaxInboxLen  = 512  // the inbox hint, e.g. a multiaddr
	sigLen       = 64
	txtChunk     = 255 // the most bytes in one DNS character-string
)

// Errors. Every record failure wraps ErrRecord; a well-formed record whose
// signature fails wraps ErrSignature.
var (
	ErrRecord    = errors.New("handle: malformed record")
	ErrSignature = errors.New("handle: bad signature")
)

func recordErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRecord, fmt.Sprintf(format, args...))
}

// Record is a parsed handle record. It does not name its handle: the handle
// is where the record was found, and Verify binds the two.
//
// Record is comparable, so two resolvers' answers can be checked with ==.
type Record struct {
	Key    identity.PublicKey
	Issued int64  // unix seconds, as signed
	Inbox  string // inbox hint; may be empty
	Sig    [sigLen]byte
}

// IssuedAt is Issued as a time.
func (r *Record) IssuedAt() time.Time { return time.Unix(r.Issued, 0) }

// NewRecord builds and signs the record that lets id claim handle h.
func NewRecord(id *identity.Identity, h string, issued time.Time, inbox string) (*Record, error) {
	if err := Validate(h); err != nil {
		return nil, err
	}
	r := &Record{Key: id.Public(), Issued: issued.Unix(), Inbox: inbox}
	if err := r.checkFields(); err != nil {
		return nil, err
	}
	copy(r.Sig[:], id.Sign(LabelClaim, ClaimMessage(h, r.Key, r.Issued, r.Inbox)))
	if len(r.String()) > MaxRecordLen {
		return nil, recordErr("longer than %d bytes", MaxRecordLen)
	}
	return r, nil
}

func (r *Record) checkFields() error {
	if r.Issued < 0 {
		return recordErr("negative issue time")
	}
	if len(r.Inbox) > MaxInboxLen {
		return recordErr("inbox hint longer than %d bytes", MaxInboxLen)
	}
	for i := 0; i < len(r.Inbox); i++ {
		if c := r.Inbox[i]; c <= ' ' || c > '~' || c == ';' {
			return recordErr("inbox hint has byte %#02x", c)
		}
	}
	return nil
}

// ClaimMessage is the message signed, after the label, by a handle claim
// (spec/handle.md §3). Every variable-length field carries a length prefix,
// so no two different claims encode to the same bytes:
//
//	u8 len(handle) ‖ handle ‖ key (32 bytes) ‖ u64 issued ‖ u16 len(inbox) ‖ inbox
//
// The key is the raw 32-byte public key, not its base32 text. h must be a
// valid handle and inbox at most MaxInboxLen bytes, so both lengths fit.
func ClaimMessage(h string, key identity.PublicKey, issued int64, inbox string) []byte {
	m := make([]byte, 0, 1+len(h)+len(key)+8+2+len(inbox))
	m = append(m, byte(len(h)))
	m = append(m, h...)
	m = append(m, key[:]...)
	m = binary.BigEndian.AppendUint64(m, uint64(issued))
	m = binary.BigEndian.AppendUint16(m, uint16(len(inbox)))
	return append(m, inbox...)
}

// Verify checks that the record's signature claims handle h.
func (r *Record) Verify(h string) error {
	if err := Validate(h); err != nil {
		return err
	}
	if err := r.checkFields(); err != nil {
		return err
	}
	if !identity.Verify(r.Key, LabelClaim, ClaimMessage(h, r.Key, r.Issued, r.Inbox), r.Sig[:]) {
		return fmt.Errorf("%w for %s", ErrSignature, h)
	}
	return nil
}

// String is the record's canonical text. ParseRecord(r.String()) gives back
// r. The inbox field is left out when the hint is empty.
func (r *Record) String() string {
	var b strings.Builder
	b.WriteString("v=" + Version)
	b.WriteString("; k=" + r.Key.String())
	b.WriteString("; t=" + strconv.FormatInt(r.Issued, 10))
	if r.Inbox != "" {
		b.WriteString("; i=" + r.Inbox)
	}
	b.WriteString("; s=" + base64.StdEncoding.EncodeToString(r.Sig[:]))
	return b.String()
}

// TXTStrings splits the canonical text into DNS character-strings of at most
// 255 bytes, ready to publish as one TXT record. Readers join them back
// together before parsing.
func (r *Record) TXTStrings() []string {
	s := r.String()
	var out []string
	for len(s) > txtChunk {
		out = append(out, s[:txtChunk])
		s = s[txtChunk:]
	}
	return append(out, s)
}

// isCandidate reports whether text is a v1 handle record, as opposed to some
// other TXT record at the same name or a record of a future version. Only
// candidates are parsed; everything else is ignored.
func isCandidate(text string) bool {
	rest, ok := strings.CutPrefix(text, "v="+Version)
	return ok && (rest == "" || rest[0] == ';' || rest[0] == ' ' || rest[0] == '\t')
}

// ParseRecord parses record text strictly (spec/handle.md §2): printable
// ASCII only, "v=oa1" first, each of k, t, s exactly once, i at most once,
// and no other fields. Unknown fields are rejected rather than ignored
// because they would not be covered by the signature; new fields need a new
// version. Values must be in canonical form, so a record has exactly one
// accepted spelling up to whitespace around fields.
func ParseRecord(text string) (*Record, error) {
	if len(text) > MaxRecordLen {
		return nil, recordErr("longer than %d bytes", MaxRecordLen)
	}
	for i := 0; i < len(text); i++ {
		if c := text[i]; (c < ' ' || c > '~') && c != '\t' {
			return nil, recordErr("byte %#02x at offset %d", c, i)
		}
	}
	fields := strings.Split(text, ";")
	// One trailing ";" is tolerated, as in DKIM and DMARC records.
	if len(fields) > 1 && strings.TrimSpace(fields[len(fields)-1]) == "" {
		fields = fields[:len(fields)-1]
	}
	var (
		r    Record
		seen = map[string]bool{}
	)
	for n, f := range fields {
		f = strings.Trim(f, " \t")
		key, val, ok := strings.Cut(f, "=")
		if !ok || key == "" {
			return nil, recordErr("field %d is not key=value", n+1)
		}
		if strings.ContainsAny(key+val, " \t") {
			return nil, recordErr("field %d has whitespace inside it", n+1)
		}
		if seen[key] {
			return nil, recordErr("duplicate field %q", key)
		}
		seen[key] = true
		if (n == 0) != (key == "v") {
			return nil, recordErr("v must be the first field")
		}
		if err := r.setField(key, val); err != nil {
			return nil, err
		}
	}
	for _, k := range []string{"v", "k", "t", "s"} {
		if !seen[k] {
			return nil, recordErr("missing field %q", k)
		}
	}
	if seen["i"] && r.Inbox == "" {
		return nil, recordErr("empty inbox hint; leave the field out instead")
	}
	if err := r.checkFields(); err != nil {
		return nil, err
	}
	return &r, nil
}

func (r *Record) setField(key, val string) error {
	switch key {
	case "v":
		if val != Version {
			return recordErr("unsupported version %q", val)
		}
	case "k":
		pk, err := identity.ParsePublicKeyString(val)
		if err != nil {
			return fmt.Errorf("%w: key: %w", ErrRecord, err)
		}
		// ParsePublicKeyString accepts uppercase and stray low bits in the
		// last character; only the canonical spelling is accepted here.
		if pk.String() != val {
			return recordErr("key is not in canonical base32")
		}
		r.Key = pk
	case "t":
		t, err := strconv.ParseInt(val, 10, 64)
		if err != nil || t < 0 || strconv.FormatInt(t, 10) != val {
			return recordErr("issue time %q is not a canonical non-negative integer", val)
		}
		r.Issued = t
	case "i":
		r.Inbox = val
	case "s":
		sig, err := base64.StdEncoding.Strict().DecodeString(val)
		if err != nil || len(sig) != sigLen {
			return recordErr("signature is not %d bytes of padded base64", sigLen)
		}
		copy(r.Sig[:], sig)
	default:
		return recordErr("unknown field %q", key)
	}
	return nil
}
