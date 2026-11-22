package main

import (
	"context"
	"strings"
	"testing"
)

func TestTUINeedsTerminal(t *testing.T) {
	t.Parallel()
	r := runOpts(context.Background(), opts{}, "tui")
	if r.code != exitError || !strings.Contains(r.stderr, "tui needs a terminal") {
		t.Fatalf("tui off a terminal: %+v", r)
	}
	if r := runOpts(context.Background(), opts{}, "tui", "--json"); r.code != exitUsage {
		t.Fatalf("tui --json: %+v", r)
	}
	if r := runOpts(context.Background(), opts{}, "tui", "extra"); r.code != exitUsage {
		t.Fatalf("tui extra: %+v", r)
	}
}

func TestTUINoIdentity(t *testing.T) {
	t.Parallel()
	dir := shortDir(t)
	secret := func(string) ([]byte, error) { return nil, nil }
	r := runOpts(context.Background(), opts{tty: true, secret: secret}, "--data-dir", dir, "tui", "--embedded")
	if r.code != exitNotRunning || !strings.Contains(r.stderr, "openaimd init") {
		t.Fatalf("tui with no identity: %+v", r)
	}
}
