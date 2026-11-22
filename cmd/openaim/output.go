package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/aghman/openaim/internal/apipb"
	"github.com/aghman/openaim/internal/termtext"
)

// Everything printed from the daemon (petnames, handles, groups, IMs, away
// messages, error text) may come from another person, and this is a
// terminal. The daemon rejects control characters in what it accepts, but
// the CLI cleans what it prints anyway, with the rules in internal/termtext.
var (
	unsafeRune = termtext.Unsafe
	clean      = termtext.Clean
	cleanText  = termtext.CleanText
)

// JSON output.

var protoJSON = protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}

// marshalJSON encodes v as one compact line of JSON. Values that are proto
// messages use the proto3 JSON mapping with the .proto field names. Unsafe
// runes inside strings are escaped (\uXXXX), so the line is as safe on a
// terminal as it is faithful to the data.
func marshalJSON(v any) ([]byte, error) {
	var raw []byte
	var err error
	if m, ok := v.(proto.Message); ok {
		raw, err = protoJSON.Marshal(m)
	} else {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		err = enc.Encode(v)
		raw = buf.Bytes()
	}
	if err != nil {
		return nil, err
	}
	// protojson varies its whitespace on purpose; normalize it.
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, err
	}
	out := escapeUnsafe(buf.Bytes())
	return append(out, '\n'), nil
}

// escapeUnsafe rewrites unsafe runes in valid JSON as \u escapes. They can
// only occur inside strings, where an escape means the same thing.
func escapeUnsafe(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		if unsafeRune(r) {
			if r > 0xFFFF {
				r1, r2 := utf16Pair(r)
				out = fmt.Appendf(out, `\u%04x\u%04x`, r1, r2)
			} else {
				out = fmt.Appendf(out, `\u%04x`, r)
			}
		} else {
			out = append(out, b[:n]...)
		}
		b = b[n:]
	}
	return out
}

func utf16Pair(r rune) (rune, rune) {
	r -= 0x10000
	return 0xD800 + (r>>10)&0x3FF, 0xDC00 + r&0x3FF
}

// protoRaw is a proto message as embedded JSON.
func protoRaw(m proto.Message) (json.RawMessage, error) {
	b, err := protoJSON.Marshal(m)
	return json.RawMessage(b), err
}

// emit prints one JSON result.
func (cl *cli) emit(v any) error {
	b, err := marshalJSON(v)
	if err != nil {
		return err
	}
	_, err = cl.e.stdout.Write(b)
	return err
}

// Human output.

// style colors text when stdout is a terminal and NO_COLOR is unset.
type style struct{ on bool }

func (cl *cli) style() style {
	return style{on: cl.e.stdoutTTY && !cl.g.json && cl.e.getenv("NO_COLOR") == "" && cl.e.getenv("TERM") != "dumb"}
}

const (
	bold   = "1"
	dim    = "2"
	green  = "32"
	yellow = "33"
	red    = "31"
)

func (s style) paint(code, text string) string {
	if !s.on || code == "" || text == "" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

// cell is one table cell: already-clean text and an optional color.
type cell struct {
	text  string
	color string
}

// table aligns columns by display width, coloring cells after padding so
// escape codes don't throw the widths off.
type table struct{ rows [][]cell }

func (t *table) row(cells ...cell) { t.rows = append(t.rows, cells) }

func (t *table) write(w io.Writer, s style) {
	var widths []int
	for _, r := range t.rows {
		for i, c := range r {
			if i >= len(widths) {
				widths = append(widths, 0)
			}
			widths[i] = max(widths[i], displayWidth(c.text))
		}
	}
	var b strings.Builder
	for _, r := range t.rows {
		var line strings.Builder
		for i, c := range r {
			if i > 0 {
				line.WriteString("  ")
			}
			line.WriteString(s.paint(c.color, c.text))
			if i < len(r)-1 {
				line.WriteString(strings.Repeat(" ", widths[i]-displayWidth(c.text)))
			}
		}
		b.WriteString(strings.TrimRight(line.String(), " "))
		b.WriteByte('\n')
	}
	io.WriteString(w, b.String())
}

// displayWidth is how many terminal columns s takes, roughly.
var displayWidth = termtext.Width

// Formatting of API values.

func buddyName(b *pb.Buddy) string {
	switch {
	case b.GetPetname() != "":
		return clean(b.GetPetname())
	case b.GetHandle() != "":
		return clean(b.GetHandle())
	}
	return clean(b.GetKeyId())
}

func buddyStateName(s pb.BuddyState) string {
	switch s {
	case pb.BuddyState_BUDDY_STATE_PENDING_OUT:
		return "pending-out"
	case pb.BuddyState_BUDDY_STATE_PENDING_IN:
		return "pending-in"
	case pb.BuddyState_BUDDY_STATE_ACCEPTED:
		return "accepted"
	case pb.BuddyState_BUDDY_STATE_BLOCKED:
		return "blocked"
	}
	return "unknown"
}

func presenceName(s pb.PresenceState) string {
	switch s {
	case pb.PresenceState_PRESENCE_STATE_ONLINE:
		return "online"
	case pb.PresenceState_PRESENCE_STATE_AWAY:
		return "away"
	case pb.PresenceState_PRESENCE_STATE_OFFLINE:
		return "offline"
	}
	return "unknown"
}

func deliveryName(s pb.DeliveryState) string {
	switch s {
	case pb.DeliveryState_DELIVERY_STATE_QUEUED:
		return "queued"
	case pb.DeliveryState_DELIVERY_STATE_ACKED:
		return "delivered"
	case pb.DeliveryState_DELIVERY_STATE_FAILED:
		return "failed"
	}
	return ""
}

// presenceText is "online", or `away: "message"`.
func presenceText(p *pb.Presence) string {
	s := presenceName(p.GetState())
	if p.GetState() == pb.PresenceState_PRESENCE_STATE_AWAY && p.GetAwayMessage() != "" {
		s += fmt.Sprintf(": %q", clean(p.GetAwayMessage()))
	}
	return s
}

func fmtTime(t *timestamppb.Timestamp) string {
	if t == nil {
		return "-"
	}
	return t.AsTime().Local().Format("2006-01-02 15:04:05")
}

func fmtDuration(d *durationpb.Duration) string {
	if d == nil {
		return "-"
	}
	return d.AsDuration().Round(time.Second).String()
}

// safetyGroups lays a safety number out as 8 groups of 5 digits, in two
// rows of four. Anything else is printed as it came.
func safetyGroups(sn string) []string {
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		if r == ' ' || r == '-' {
			return -1
		}
		return 'x'
	}, sn)
	if len(digits) != 40 || strings.ContainsRune(digits, 'x') {
		return []string{clean(sn)}
	}
	var groups []string
	for i := 0; i < 40; i += 5 {
		groups = append(groups, digits[i:i+5])
	}
	return []string{strings.Join(groups[:4], " "), strings.Join(groups[4:], " ")}
}

// printPhrase shows a recovery phrase as numbered words, four per row.
func printPhrase(w io.Writer, phrase string) {
	words := strings.Fields(clean(phrase))
	var b strings.Builder
	fmt.Fprintln(&b, "RECOVERY PHRASE: anyone who has these 24 words can become you. Keep them")
	fmt.Fprintln(&b, "somewhere safe and offline; they restore this identity with `openaimd init --restore`.")
	fmt.Fprintln(&b)
	for i := 0; i < len(words); i += 4 {
		for j := i; j < i+4 && j < len(words); j++ {
			fmt.Fprintf(&b, "  %2d. %-10s", j+1, words[j])
		}
		b.WriteString("\n")
	}
	io.WriteString(w, b.String())
}
