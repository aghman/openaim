package termtext

import (
	"slices"
	"testing"
)

func TestClean(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"plain":                "plain",
		"a\x1b[31mb":           "a\ufffd[31mb",
		"tab\tnl\n":            "tab nl ",
		"c1\u0085\u009b":       "c1\ufffd\ufffd",
		"bidi\u202e\u2066":     "bidi\ufffd\ufffd",
		"marks\u200e\u061c":    "marks\ufffd\ufffd",
		"ls\u2028\u2029":       "ls\ufffd\ufffd",
		"bad\xffutf8":          "bad\ufffdutf8",
		"emoji 👋\U0001f3fd ok": "emoji 👋\U0001f3fd ok",
		"del\x7f":              "del\ufffd",
		"osc\x1b]0;t\x07":      "osc\ufffd]0;t\ufffd",
	}
	for in, want := range cases {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCleanText(t *testing.T) {
	t.Parallel()
	if got := CleanText("a\nb\tc\x1b", "  "); got != "a\n  b\tc\ufffd" {
		t.Errorf("CleanText = %q", got)
	}
}

func TestLines(t *testing.T) {
	t.Parallel()
	got := Lines("one\r\ntwo\tx\n\x1b[2Jthree")
	want := []string{"one", "two x", "\ufffd[2Jthree"}
	if !slices.Equal(got, want) {
		t.Errorf("Lines = %q, want %q", got, want)
	}
}

func TestWidth(t *testing.T) {
	t.Parallel()
	if got := Width("日本ab\u0301"); got != 6 {
		t.Errorf("Width = %d", got)
	}
}
