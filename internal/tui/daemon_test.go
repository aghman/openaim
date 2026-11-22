package tui

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/aghman/openaim/internal/api"
	"github.com/aghman/openaim/internal/daemon"
	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/keystore"
)

// The TUI against a real in-process daemon over its socket: send an IM
// through the model, see it (and a reply) in the history, and ride out a
// daemon restart.
func TestWithDaemon(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("", "oat") // short: Unix socket paths are limited
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	pass := []byte("correct horse battery staple")
	fast := keystore.Params{Time: 1, MemoryKiB: 8 << 10, Threads: 1}
	ctx := context.Background()
	me, err := daemon.Init(ctx, daemon.InitConfig{DataDir: dir, Passphrase: pass, KeystoreParams: fast})
	if err != nil {
		t.Fatal(err)
	}
	cfg := api.Config{Config: daemon.Config{DataDir: dir, Passphrase: pass, KeystoreParams: fast}}
	d, err := api.Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Stop() })

	bob, err := identity.FromSeed(bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	bobKey := bob.Public().String()
	if _, err := d.Node().AddBuddy(ctx, bobKey, "Bob", ""); err != nil {
		t.Fatal(err)
	}

	opt := testOptions(DialSocket(d.SocketPath()))
	opt.Now = time.Now
	opt.BackoffMin, opt.BackoffMax = 10*time.Millisecond, 50*time.Millisecond
	h := start(t, opt)
	label := "⚠ " + bob.Public().KeyID() + " Bob"
	h.waitView("Buddy List", label+" (pending)", me.Public().KeyID()+" online")

	h.selectBuddy(bobKey)
	h.keys("enter")
	h.waitView("No messages yet with Bob", "Bob · "+bob.Public().KeyID()+" · offline · pending · ⚠ unverified")
	h.keys("hello from the tui", "enter")
	h.waitView("me: hello from the tui  [queued]")

	// The daemon has it.
	hist, err := d.Node().History(ctx, bobKey, 10)
	if err != nil || len(hist) != 1 || hist[0].Text != "hello from the tui" {
		t.Fatalf("daemon history %v, %v", hist, err)
	}

	// A reply arrives. (History orders by millisecond store time, so let
	// the clock move past our send first.)
	time.Sleep(3 * time.Millisecond)
	p, err := bob.Pair(me.Public())
	if err != nil {
		t.Fatal(err)
	}
	k := frame.NewConvKey(p.Send)
	now := time.Now()
	in := frame.Inner{Type: frame.IM, Time: frame.Timestamp(now), Seq: 1, Body: []byte("yeah if my radio reaches lol")}
	s, err := frame.Seal(k, k.Tag(frame.Day(now)), frame.LayoutMesh, in.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range s.Frames {
		if _, err := d.Node().HandleFrame(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	h.waitView("Bob: yeah if my radio reaches lol")

	// The daemon restarts: the TUI says so, then reconnects by itself and
	// reloads the conversation from the daemon's history.
	d.Stop()
	h.waitView("Lost the connection to openaimd.", "`openaimd run`")
	d2, err := api.Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d2.Stop)
	h.waitView("Buddy List", "me: hello from the tui  [queued]", "Bob: yeah if my radio reaches lol")
	h.keys("still there?", "enter")
	h.waitView("me: still there?")
}
