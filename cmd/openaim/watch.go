package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/aghman/openaim/internal/apipb"
)

var cmdWatch = &command{
	name: "watch", summary: "print daemon events as they happen, until the daemon stops",
	help: `Human lines, or with --json one event object per line. The first event is
always "ready" (in --json mode a {"ready":{}} line; otherwise a note on
stderr): once it appears, the subscription is in place and nothing after it
is missed. watch exits 0 when the daemon shuts down or on Ctrl-C, and 1 if
it falls too far behind (events were dropped; run it again). --timeout
bounds only the wait for "ready".
`,
	setup: func(*flag.FlagSet) runFunc {
		return func(ctx context.Context, cl *cli, args []string) error {
			if err := nargs(args, 0, 0); err != nil {
				return err
			}
			return cl.watch(ctx)
		}
	},
}

func (cl *cli) watch(ctx context.Context) error {
	c, err := cl.client()
	if err != nil {
		return err
	}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var timedOut atomic.Bool
	var readyTimer *time.Timer
	if cl.g.timeout > 0 {
		readyTimer = time.AfterFunc(cl.g.timeout, func() { timedOut.Store(true); cancel() })
		defer readyTimer.Stop()
	}
	stream, err := c.SubscribeEvents(sctx, &pb.SubscribeEventsRequest{})
	if err != nil {
		return cl.rpcErr(err)
	}
	ready := false
	var names map[string]string
	s := cl.style()
	for {
		ev, err := stream.Recv()
		if err != nil {
			switch {
			case !ready && timedOut.Load():
				return cl.rpcErr(status.Error(codes.DeadlineExceeded, "no ready event"))
			case ctx.Err() != nil:
				return nil // interrupted: the normal way to stop watching
			case !ready:
				return cl.rpcErr(err)
			case status.Code(err) == codes.Unavailable:
				if !cl.g.json {
					fmt.Fprintln(cl.e.stderr, "openaimd shut down; done watching.")
				}
				return nil
			case status.Code(err) == codes.ResourceExhausted:
				return &cliError{code: exitError, kind: "lagged", msg: "fell too far behind the daemon's events, so some were dropped",
					hint: "run watch again, and reload any state you keep"}
			case errors.Is(err, context.Canceled):
				return nil
			}
			return cl.rpcErr(err)
		}
		if !ready {
			if ev.GetReady() == nil {
				return fmt.Errorf("event stream did not start with ready")
			}
			ready = true
			if readyTimer != nil && !readyTimer.Stop() && timedOut.Load() {
				return cl.rpcErr(status.Error(codes.DeadlineExceeded, "no ready event"))
			}
			if !cl.g.json {
				// Names for messages, loaded after ready so no change is missed.
				if names, err = cl.buddyNames(ctx); err != nil {
					return err
				}
				fmt.Fprintln(cl.e.stderr, "Watching openaimd events (Ctrl-C to stop).")
			}
		}
		if cl.g.json {
			if err := cl.emit(ev); err != nil {
				return err
			}
			continue
		}
		if line := formatEvent(s, ev, names); line != "" {
			fmt.Fprintln(cl.e.stdout, line)
		}
	}
}

// formatEvent is one human line for an event, and keeps names current.
func formatEvent(s style, ev *pb.Event, names map[string]string) string {
	at := s.paint(dim, ev.GetTime().AsTime().Local().Format("15:04:05")) + " "
	buddy := func(b *pb.Buddy) string {
		return fmt.Sprintf("%s (%s, %s, %s)", buddyName(b), clean(b.GetKeyId()), clean(b.GetGroup()), buddyStateName(b.GetState()))
	}
	switch k := ev.GetKind().(type) {
	case *pb.Event_Ready:
		return ""
	case *pb.Event_BuddyAdded:
		names[k.BuddyAdded.GetIdentityKey()] = buddyName(k.BuddyAdded)
		return at + "buddy added: " + buddy(k.BuddyAdded)
	case *pb.Event_BuddyChanged:
		names[k.BuddyChanged.GetIdentityKey()] = buddyName(k.BuddyChanged)
		v := "unverified"
		if k.BuddyChanged.GetVerified() {
			v = "verified"
		}
		return at + "buddy changed: " + buddy(k.BuddyChanged) + ", " + v
	case *pb.Event_BuddyRemoved:
		delete(names, k.BuddyRemoved.GetIdentityKey())
		return at + "buddy removed: " + buddy(k.BuddyRemoved)
	case *pb.Event_BuddyRequest:
		names[k.BuddyRequest.GetIdentityKey()] = buddyName(k.BuddyRequest)
		return at + s.paint(bold, "buddy request") + " from " + buddy(k.BuddyRequest) + ": " + requestLine(k.BuddyRequest)
	case *pb.Event_MessageQueued:
		m := k.MessageQueued
		return at + fmt.Sprintf("IM to %s queued (%s): ", nameFor(names, m.GetBuddyKey()), clean(m.GetMsgId())) +
			cleanText(m.GetText(), strings.Repeat(" ", 9))
	case *pb.Event_MessageReceived:
		m := k.MessageReceived
		return at + s.paint(bold, nameFor(names, m.GetBuddyKey())) + ": " + cleanText(m.GetText(), strings.Repeat(" ", 9))
	case *pb.Event_PresenceChanged:
		return at + "presence: " + presenceText(k.PresenceChanged)
	case *pb.Event_BuddyPresence:
		p := k.BuddyPresence
		names[p.GetBuddy().GetIdentityKey()] = buddyName(p.GetBuddy())
		line := at + s.paint(bold, buddyName(p.GetBuddy())) + " is " + presenceText(p.GetBuddy().GetPresence())
		switch {
		case p.GetDoorOpen():
			line += " (signed on)"
		case p.GetDoorClose():
			line += " (" + clean(p.GetReason()) + ")"
		}
		return line
	case *pb.Event_MessageUpdated:
		u := k.MessageUpdated
		return at + fmt.Sprintf("IM to %s %s (%s)", nameFor(names, u.GetBuddyKey()), deliveryName(u.GetDelivery()), clean(u.GetMsgId()))
	}
	return at + "unknown event"
}
