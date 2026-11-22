package frame

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/aghman/openaim/internal/identity"
)

// FIRST_CONTACT frames (spec/wire.md §11, design §8.5) carry a request from
// someone who isn't a buddy yet. They use a one-way handshake modelled on
// Noise X (e, es, s, ss): the sender's identity key travels encrypted, and
// the payload is authenticated by static-static DH rather than a signature,
// so the request is deniable. There is no recipient hint: a recipient tries
// every FIRST_CONTACT frame it hears, at one X25519 per frame.

// Labels (spec/wire.md §2).
const (
	labelFC        = "openaim/v1/first-contact"
	labelFCES      = "openaim/v1/first-contact/es"
	labelFCSS      = "openaim/v1/first-contact/ss"
	labelFCSIV     = "openaim/v1/first-contact/siv"
	labelFCEncS    = "openaim/v1/first-contact/s"
	labelFCPayload = "openaim/v1/first-contact/payload"
	labelFCTail    = "openaim/v1/first-contact/tail"
	labelFCDedup   = "openaim/v1/first-contact/dedup"
)

const (
	fcHeaderLen = 1 + 32 + 8 + 1 // ver_kind | e | msg_id | frag
	fcEncSLen   = 32 + tagLen    // enc(s): the sender's Ed25519 key + tag
	// FirstContactOverhead is the cost of fragment 0, which carries enc(s).
	FirstContactOverhead = fcHeaderLen + fcEncSLen + tagLen // 106
	// FirstContactTailOverhead is the cost of each later fragment.
	FirstContactTailOverhead = fcHeaderLen + tagLen // 58
	// minInner is the shortest valid inner payload (§6): fragment 0 must
	// carry the whole inner header, so the window can be checked on it.
	minInner = 7
)

type fcLayoutInfo struct {
	kind     Kind
	frameLen int
	maxFrags int
}

// A first contact is short (a name, a greeting, a contact hint), and every
// node that hears one pays an X25519 to try it, so the limits are tight.
var fcLayouts = map[Layout]fcLayoutInfo{
	LayoutMesh: {KindFirstContact, 200, 2},
	LayoutIP:   {KindFirstContactIP, 4096, 1},
}

func fcLayoutOf(k Kind) (Layout, bool) {
	switch k {
	case KindFirstContact:
		return LayoutMesh, true
	case KindFirstContactIP:
		return LayoutIP, true
	}
	return 0, false
}

// FirstContactCapacity is the inner-payload bytes fragment index of a
// first contact carries in layout l: fragment 0 also carries enc(s).
func FirstContactCapacity(l Layout, index int) int {
	li, ok := fcLayouts[l]
	if !ok {
		return 0
	}
	if index == 0 {
		return li.frameLen - FirstContactOverhead
	}
	return li.frameLen - FirstContactTailOverhead
}

// FirstContactMaxInner is the largest inner payload a first contact carries
// in layout l.
func FirstContactMaxInner(l Layout) int {
	li, ok := fcLayouts[l]
	if !ok {
		return 0
	}
	return FirstContactCapacity(l, 0) + (li.maxFrags-1)*FirstContactCapacity(l, 1)
}

// fcCount is how many fragments an n-byte inner payload needs.
func fcCount(l Layout, n int) int {
	c0, c1 := FirstContactCapacity(l, 0), FirstContactCapacity(l, 1)
	if n <= c0 {
		return 1
	}
	return 1 + (n-c0+c1-1)/c1
}

// fcChunk is fragment i's slice of inner. Every chunk but the last fills its
// fragment.
func fcChunk(l Layout, inner []byte, i int) []byte {
	start := 0
	if i > 0 {
		start = FirstContactCapacity(l, 0) + (i-1)*FirstContactCapacity(l, 1)
	}
	return inner[start:min(start+FirstContactCapacity(l, i), len(inner))]
}

// FirstContactHeader is the cleartext, authenticated part of a FIRST_CONTACT
// frame.
type FirstContactHeader struct {
	Kind   Kind
	Layout Layout
	E      [32]byte // the sender's ephemeral X25519 public key
	MsgID  MsgID
	Index  int // fragment index, 0-based
	Count  int // fragments in the message
}

// Errors specific to first contact.
var (
	ErrNotFirstContact = errors.New("frame: not a FIRST_CONTACT frame")
	// ErrSelf: a first contact from an identity to itself (or to a key with
	// the same X25519 form).
	ErrSelf = errors.New("frame: first contact to self")
)

// ParseFirstContactHeader reads and checks a FIRST_CONTACT frame's header
// without any crypto: version, kind, fragment numbers, frame length, and a
// canonical encoding of e.
func ParseFirstContactHeader(b []byte) (FirstContactHeader, error) {
	var h FirstContactHeader
	if len(b) == 0 {
		return h, fmt.Errorf("%w: empty frame", ErrMalformed)
	}
	if v := b[0] >> 5; v != Version {
		return h, fmt.Errorf("%w: version %d", ErrMalformed, v)
	}
	h.Kind = Kind(b[0] & 0x1F)
	l, ok := fcLayoutOf(h.Kind)
	if !ok {
		return h, fmt.Errorf("%w: kind %d", ErrNotFirstContact, h.Kind)
	}
	h.Layout = l
	if len(b) < FirstContactTailOverhead+1 {
		return h, fmt.Errorf("%w: %d bytes", ErrMalformed, len(b))
	}
	li := fcLayouts[l]
	copy(h.E[:], b[1:33])
	copy(h.MsgID[:], b[33:41])
	h.Index, h.Count = int(b[41]>>4), int(b[41]&0x0F)+1
	switch {
	case h.Count > li.maxFrags:
		return h, fmt.Errorf("%w: %d fragments in %s first contact", ErrMalformed, h.Count, l)
	case h.Index >= h.Count:
		return h, fmt.Errorf("%w: fragment %d of %d", ErrMalformed, h.Index, h.Count)
	case len(b) > li.frameLen:
		return h, fmt.Errorf("%w: %d bytes in %s first contact", ErrMalformed, len(b), l)
	case h.Index < h.Count-1 && len(b) != li.frameLen:
		return h, fmt.Errorf("%w: short non-final fragment", ErrMalformed)
	case h.Index == 0 && len(b) < FirstContactOverhead+minInner:
		return h, fmt.Errorf("%w: fragment 0 of %d bytes", ErrMalformed, len(b))
	case !canonicalU(h.E[:]):
		return h, fmt.Errorf("%w: non-canonical ephemeral key", ErrMalformed)
	}
	return h, nil
}

// canonicalU reports whether u is a canonical X25519 u-coordinate: the top
// bit clear and the little-endian value below p = 2^255 − 19. X25519 itself
// ignores the top bit and reduces mod p, so without this check several byte
// strings would name one ephemeral key.
func canonicalU(u []byte) bool {
	if u[31]&0x80 != 0 {
		return false
	}
	if u[31] != 0x7F {
		return true
	}
	for i := 30; i >= 1; i-- {
		if u[i] != 0xFF {
			return true
		}
	}
	return u[0] < 0xED
}

func fcHeader(k Kind, e []byte, id MsgID, index, count int) []byte {
	h := make([]byte, fcHeaderLen, fcHeaderLen+fcEncSLen)
	h[0] = VerKind(k)
	copy(h[1:33], e)
	copy(h[33:41], id[:])
	h[41] = fragByte(index, count)
	return h
}

// Key schedule (spec/wire.md §11.2).
//
//	h_R    = SHA-256("openaim/v1/first-contact" ‖ R_ed)
//	ck1    = HKDF(ikm = es, salt = h_R, info = "openaim/v1/first-contact/es" ‖ e)
//	ck2    = HKDF(ikm = ss, salt = ck1, info = "openaim/v1/first-contact/ss" ‖ S_ed)
//	K_siv  = Expand(ck2, "openaim/v1/first-contact/siv")
//	msg_id = HMAC(K_siv, inner)[:8]
//	K_x    = Expand(ck, label_x ‖ msg_id ‖ count_u8 ‖ layout_u8)

func fcCK1(recipient identity.PublicKey, e, es []byte) []byte {
	hR := sha256.Sum256(append([]byte(labelFC), recipient[:]...))
	return hkdfKey(es, hR[:], labelFCES+string(e))
}

func fcCK2(ck1, ss []byte, sender identity.PublicKey) []byte {
	return hkdfKey(ss, ck1, labelFCSS+string(sender[:]))
}

func fcSIV(ck2 []byte) []byte { return expand(ck2, labelFCSIV) }

func fcMsgID(siv, inner []byte) MsgID {
	m := hmac.New(sha256.New, siv)
	m.Write(inner)
	var id MsgID
	copy(id[:], m.Sum(nil))
	return id
}

// fcKey derives one AEAD key. Binding msg_id, count and layout means a
// (key, nonce) pair recurs only for the same plaintext and header, even if
// the sender's randomness repeats e (spec/wire.md §11.4).
func fcKey(ck []byte, label string, id MsgID, count int, l Layout) []byte {
	info := make([]byte, 0, len(label)+10)
	info = append(info, label...)
	info = append(info, id[:]...)
	info = append(info, byte(count), byte(l))
	return expand(ck, string(info))
}

func hkdfKey(ikm, salt []byte, info string) []byte {
	k, err := hkdf.Key(sha256.New, ikm, salt, info, 32)
	if err != nil {
		panic(err) // only fails for absurd lengths
	}
	return k
}

func expand(prk []byte, info string) []byte {
	k, err := hkdf.Expand(sha256.New, prk, info, 32)
	if err != nil {
		panic(err)
	}
	return k
}

func aeadFor(key []byte) cipher.AEAD {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err) // the key is always 32 bytes
	}
	return a
}

// SealedFirstContact is a first contact sealed into frames. As with DATA,
// the frames are the message from then on: the sender persists them, and
// retries re-send exactly these bytes. Sealing again draws a new ephemeral
// key, which makes a different (unlinkable) message.
type SealedFirstContact struct {
	E      [32]byte
	MsgID  MsgID
	Layout Layout
	Frames [][]byte
}

// SealFirstContact encrypts an inner payload (Inner.Marshal output) from
// sender to recipient as FIRST_CONTACT frames in layout l. random supplies
// the 32-byte ephemeral key; nil means crypto/rand. Tests pass a fixed
// reader for golden vectors.
func SealFirstContact(sender *identity.Identity, recipient identity.PublicKey, l Layout, inner []byte, random io.Reader) (*SealedFirstContact, error) {
	if _, ok := fcLayouts[l]; !ok {
		return nil, fmt.Errorf("frame: unknown layout %d", l)
	}
	if _, err := ParseInner(inner); err != nil {
		return nil, err
	}
	if len(inner) > FirstContactMaxInner(l) {
		return nil, fmt.Errorf("%w: %d bytes, %s first contact carries %d", ErrTooLarge, len(inner), l, FirstContactMaxInner(l))
	}
	if _, err := identity.ParsePublicKey(recipient[:]); err != nil {
		return nil, err
	}
	rx, err := recipient.X25519()
	if err != nil {
		return nil, err
	}
	me := sender.Public()
	sx, err := me.X25519()
	if err != nil {
		return nil, err
	}
	if me == recipient || bytes.Equal(sx.Bytes(), rx.Bytes()) {
		return nil, ErrSelf
	}

	if random == nil {
		random = rand.Reader
	}
	var eSeed [32]byte
	if _, err := io.ReadFull(random, eSeed[:]); err != nil {
		return nil, fmt.Errorf("frame: ephemeral key: %w", err)
	}
	// NewPrivateKey clamps the scalar, as RFC 7748 does.
	ePriv, err := ecdh.X25519().NewPrivateKey(eSeed[:])
	if err != nil {
		return nil, err
	}
	es, err := ePriv.ECDH(rx)
	if err != nil {
		return nil, err
	}
	ss, err := sender.DH(rx)
	if err != nil {
		return nil, err
	}
	return sealFirstContact(me, recipient, l, inner, ePriv.PublicKey().Bytes(), es, ss), nil
}

// sealFirstContact builds the frames from the DH outputs. Inputs are
// checked by the caller; tests call it directly to build hostile frames.
func sealFirstContact(me, recipient identity.PublicKey, l Layout, inner, e, es, ss []byte) *SealedFirstContact {
	ck1 := fcCK1(recipient, e, es)
	ck2 := fcCK2(ck1, ss, me)
	id := fcMsgID(fcSIV(ck2), inner)
	count := fcCount(l, len(inner))

	s := &SealedFirstContact{MsgID: id, Layout: l, Frames: make([][]byte, count)}
	copy(s.E[:], e)
	for i := range count {
		chunk := fcChunk(l, inner, i)
		f := fcHeader(fcLayouts[l].kind, e, id, i, count)
		if i == 0 {
			ad := bytes.Clone(f)
			f = aeadFor(fcKey(ck1, labelFCEncS, id, count, l)).Seal(f, nonce(0), me[:], ad)
			ad = bytes.Clone(f) // header ‖ enc(s)
			f = aeadFor(fcKey(ck2, labelFCPayload, id, count, l)).Seal(f, nonce(0), chunk, ad)
		} else {
			ad := bytes.Clone(f)
			f = aeadFor(fcKey(ck1, labelFCTail, id, count, l)).Seal(f, nonce(i), chunk, ad)
		}
		s.Frames[i] = f
	}
	return s
}

// fcOpened is one authenticated first-contact fragment.
type fcOpened struct {
	pt []byte
	// Set for fragment 0 only.
	sender identity.PublicKey
	siv    []byte
}

// openFirstContact trial-decrypts one frame whose header h was parsed from
// it. Every failure is ErrAuth, so a frame meant for someone else, a forged
// frame and a bad sender key look the same.
func openFirstContact(me *identity.Identity, h FirstContactHeader, b []byte) (fcOpened, error) {
	var o fcOpened
	ex, err := ecdh.X25519().NewPublicKey(h.E[:])
	if err != nil {
		return o, ErrAuth
	}
	es, err := me.DH(ex) // fails for a small-order e
	if err != nil {
		return o, ErrAuth
	}
	myKey := me.Public()
	ck1 := fcCK1(myKey, h.E[:], es)
	if h.Index > 0 {
		pt, err := aeadFor(fcKey(ck1, labelFCTail, h.MsgID, h.Count, h.Layout)).
			Open(nil, nonce(h.Index), b[fcHeaderLen:], b[:fcHeaderLen])
		if err != nil {
			return o, ErrAuth
		}
		o.pt = pt
		return o, nil
	}

	encS := b[fcHeaderLen : fcHeaderLen+fcEncSLen]
	sb, err := aeadFor(fcKey(ck1, labelFCEncS, h.MsgID, h.Count, h.Layout)).Open(nil, nonce(0), encS, b[:fcHeaderLen])
	if err != nil {
		return o, ErrAuth
	}
	sender, err := identity.ParsePublicKey(sb)
	if err != nil {
		return o, ErrAuth
	}
	sx, err := sender.X25519()
	if err != nil {
		return o, ErrAuth
	}
	mx, err := myKey.X25519()
	if err != nil {
		return o, ErrAuth
	}
	if sender == myKey || bytes.Equal(sx.Bytes(), mx.Bytes()) {
		return o, ErrAuth
	}
	ss, err := me.DH(sx)
	if err != nil {
		return o, ErrAuth
	}
	ck2 := fcCK2(ck1, ss, sender)
	pt, err := aeadFor(fcKey(ck2, labelFCPayload, h.MsgID, h.Count, h.Layout)).
		Open(nil, nonce(0), b[fcHeaderLen+fcEncSLen:], b[:fcHeaderLen+fcEncSLen])
	if err != nil {
		return o, ErrAuth
	}
	o.pt, o.sender, o.siv = pt, sender, fcSIV(ck2)
	return o, nil
}

// MaxFirstContactPartials bounds incomplete first contacts held at once.
// Anyone can make valid fragments with keys of their own, so this is a
// global bound; rate limiting first contacts is the caller's job.
const MaxFirstContactPartials = 16

// FirstContact is a reassembled, authenticated, in-window first contact.
type FirstContact struct {
	// Sender is the authenticated identity key of the sender. It is not yet
	// a buddy: the UI shows it as unverified (design §5.3).
	Sender identity.PublicKey
	MsgID  MsgID
	Inner  Inner
}

// FirstContactResult describes an accepted first-contact frame.
type FirstContactResult struct {
	Status Status
	Header FirstContactHeader
	// Have is the bitmap of fragments held for this message.
	Have uint16
	// Message is set when Status is Delivered.
	Message *FirstContact
}

// FirstContactReceiver authenticates incoming FIRST_CONTACT frames for one
// identity, drops replays and reassembles requests. It is safe for
// concurrent use.
//
// Order of checks (spec/wire.md §11.5): header syntax, trial decryption, and
// for fragment 0 the sender key and the acceptance window. Only a fragment
// that passes touches dedup or reassembly state.
type FirstContactReceiver struct {
	Me    *identity.Identity
	Dedup Dedup
	Now   func() time.Time // defaults to time.Now

	mu       sync.Mutex
	partials map[fcPartialKey]*fcPartial
}

type fcPartialKey struct {
	e     [32]byte
	id    MsgID
	count int
}

type fcPartial struct {
	parts  [][]byte
	have   uint16
	first  time.Time
	sender identity.PublicKey
	siv    []byte // from fragment 0; nil until it arrives
}

func (r *FirstContactReceiver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// fcDedupTag is the dedup Tag for a first contact's fragments:
// SHA-256("openaim/v1/first-contact/dedup" ‖ e)[:8]. It keeps them apart
// from DATA conversation tags if the two share a Dedup store.
func fcDedupTag(e [32]byte) ConvTag {
	h := sha256.Sum256(append([]byte(labelFCDedup), e[:]...))
	var t ConvTag
	copy(t[:], h[:8])
	return t
}

// Accept processes one frame. Errors mean the frame was dropped:
// ErrMalformed/ErrNotFirstContact (syntax), ErrAuth (not for us, forged, or
// a bad key), ErrStale, ErrMsgID.
func (r *FirstContactReceiver) Accept(b []byte) (FirstContactResult, error) {
	h, err := ParseFirstContactHeader(b)
	if err != nil {
		return FirstContactResult{}, err
	}
	res := FirstContactResult{Header: h}
	o, err := openFirstContact(r.Me, h, b)
	if err != nil {
		return res, err
	}
	now := r.now()
	if h.Index == 0 {
		// Fragment 0 carries the timestamp: reject a stale one before it
		// touches any state. ParseFirstContactHeader guaranteed the bytes.
		if err := checkWindow(binary.BigEndian.Uint32(o.pt[2:6]), now); err != nil {
			return res, err
		}
	}
	fid := FragmentID{Tag: fcDedupTag(h.E), MsgID: h.MsgID, Frag: fragByte(h.Index, h.Count)}

	r.mu.Lock()
	if !r.Dedup.Insert(fid, now) {
		res.Status = Duplicate
		res.Have = fullMask(h.Count)
		if p := r.partials[fcPartialKey{h.E, h.MsgID, h.Count}]; p != nil {
			res.Have = p.have
		}
		r.mu.Unlock()
		return res, nil
	}
	p := r.partialFor(h, now)
	p.parts[h.Index] = o.pt
	p.have |= 1 << h.Index
	if h.Index == 0 {
		p.sender, p.siv = o.sender, o.siv
	}
	res.Have = p.have
	complete := p.have == fullMask(h.Count)
	if complete {
		delete(r.partials, fcPartialKey{h.E, h.MsgID, h.Count})
	}
	r.mu.Unlock()

	if !complete {
		res.Status = Partial
		return res, nil
	}
	inner := bytes.Join(p.parts, nil)
	// The SIV check binds every fragment, including those opened under es
	// alone, to the sender's static key.
	if want := fcMsgID(p.siv, inner); !hmac.Equal(want[:], h.MsgID[:]) {
		return res, ErrMsgID
	}
	in, err := ParseInner(inner)
	if err != nil {
		return res, err
	}
	if err := checkWindow(in.Time, now); err != nil {
		return res, err
	}
	res.Status = Delivered
	res.Message = &FirstContact{Sender: p.sender, MsgID: h.MsgID, Inner: in}
	return res, nil
}

// partialFor returns the reassembly buffer for h, creating it (and evicting
// expired buffers, then the oldest, if the table is full). Caller holds r.mu.
func (r *FirstContactReceiver) partialFor(h FirstContactHeader, now time.Time) *fcPartial {
	if r.partials == nil {
		r.partials = map[fcPartialKey]*fcPartial{}
	}
	k := fcPartialKey{h.E, h.MsgID, h.Count}
	if p := r.partials[k]; p != nil {
		return p
	}
	for k, p := range r.partials {
		if now.Sub(p.first) > PartialTTL {
			delete(r.partials, k)
		}
	}
	if len(r.partials) >= MaxFirstContactPartials {
		var oldest fcPartialKey
		var ot time.Time
		for k, p := range r.partials {
			if ot.IsZero() || p.first.Before(ot) {
				oldest, ot = k, p.first
			}
		}
		delete(r.partials, oldest)
	}
	p := &fcPartial{parts: make([][]byte, h.Count), first: now}
	r.partials[k] = p
	return p
}

// Sweep drops reassembly buffers older than PartialTTL.
func (r *FirstContactReceiver) Sweep() {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, p := range r.partials {
		if now.Sub(p.first) > PartialTTL {
			delete(r.partials, k)
		}
	}
}
