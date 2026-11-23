package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

	pb "github.com/aghman/openaim/internal/apipb"
)

// Buddy requests: invite links, accepting, declining, blocking, labels.

var (
	rpcCreateInvite = func(c pb.DaemonClient, ctx context.Context, r *pb.CreateInviteRequest) (*pb.CreateInviteResponse, error) {
		return c.CreateInvite(ctx, r)
	}
	rpcAcceptBuddy = func(c pb.DaemonClient, ctx context.Context, r *pb.AcceptBuddyRequest) (*pb.Buddy, error) {
		return c.AcceptBuddy(ctx, r)
	}
	rpcDeclineBuddy = func(c pb.DaemonClient, ctx context.Context, r *pb.DeclineBuddyRequest) (*pb.DeclineBuddyResponse, error) {
		return c.DeclineBuddy(ctx, r)
	}
	rpcBlockBuddy = func(c pb.DaemonClient, ctx context.Context, r *pb.BlockBuddyRequest) (*pb.Buddy, error) {
		return c.BlockBuddy(ctx, r)
	}
	rpcSetLabels = func(c pb.DaemonClient, ctx context.Context, r *pb.SetBuddyLabelsRequest) (*pb.Buddy, error) {
		return c.SetBuddyLabels(ctx, r)
	}
)

var cmdInvite = &command{
	name: "invite", synopsis: "[--handle HANDLE] [--contact MULTIADDR]", summary: "print our invite link",
	help: `Prints openaim:add/<key>?h=<handle>&c=<contact hint>, to share or show
as a QR code. The contact hint is a relay-circuit or mailbox address, never
your own IP address; by default it is the daemon's current relay
reservation, and --contact overrides it. --handle adds your handle (whoever
adds you verifies it).
`,
	setup: func(fs *flag.FlagSet) runFunc {
		h := fs.String("handle", "", "your handle to include")
		contact := fs.String("contact", "", "contact hint to use (a relay-circuit or mailbox multiaddr)")
		return func(ctx context.Context, cl *cli, args []string) error {
			if err := nargs(args, 0, 0); err != nil {
				return err
			}
			r, err := unary(ctx, cl, rpcCreateInvite, &pb.CreateInviteRequest{Handle: *h, ContactHint: *contact})
			if err != nil {
				return err
			}
			if cl.g.json {
				return cl.emit(r)
			}
			fmt.Fprintln(cl.e.stdout, clean(r.GetLink()))
			if r.GetNote() != "" {
				fmt.Fprintln(cl.e.stderr, "note:", clean(r.GetNote()))
			}
			return nil
		}
	},
}

// buddyCommand is a command that takes one buddy and calls rpc on it.
func buddyCommand(name, summary, help, done string, rpc func(ctx context.Context, cl *cli, buddy string) (*pb.Buddy, error)) *command {
	return &command{
		name: name, synopsis: "<buddy>", summary: summary, help: help,
		setup: func(*flag.FlagSet) runFunc {
			return func(ctx context.Context, cl *cli, args []string) error {
				if err := nargs(args, 1, 1); err != nil {
					return err
				}
				b, err := rpc(ctx, cl, args[0])
				if err != nil {
					return err
				}
				if cl.g.json {
					if b == nil {
						return cl.emit(map[string]any{name + "d": args[0]})
					}
					return cl.emit(b)
				}
				if b == nil {
					fmt.Fprintf(cl.e.stdout, "%s %s.\n", done, clean(args[0]))
					return nil
				}
				fmt.Fprintf(cl.e.stdout, "%s %s (%s); %s.\n", done, buddyName(b), clean(b.GetKeyId()), buddyStateName(b.GetState()))
				return nil
			}
		},
	}
}

var cmdAccept = buddyCommand("accept", "accept a buddy request",
	`Accepts a pending-in buddy's request: they become a buddy and get your
presence key and reachability. Nothing about your presence is shared before
this. Exits 1 if they haven't asked.
`, "Accepted", func(ctx context.Context, cl *cli, buddy string) (*pb.Buddy, error) {
		return unary(ctx, cl, rpcAcceptBuddy, &pb.AcceptBuddyRequest{Buddy: buddy})
	})

var cmdDecline = buddyCommand("decline", "decline a buddy request (nothing is sent)",
	`Deletes a pending-in buddy's request without telling them. They can ask
again; block stops that.
`, "Declined", func(ctx context.Context, cl *cli, buddy string) (*pb.Buddy, error) {
		_, err := unary(ctx, cl, rpcDeclineBuddy, &pb.DeclineBuddyRequest{Buddy: buddy})
		return nil, err
	})

var cmdBlock = buddyCommand("block", "block a buddy: drop their frames and requests",
	`Blocks a buddy in any state: their messages and requests are dropped
unread and nothing more is sent to them. Remove the buddy to unblock.
`, "Blocked", func(ctx context.Context, cl *cli, buddy string) (*pb.Buddy, error) {
		return unary(ctx, cl, rpcBlockBuddy, &pb.BlockBuddyRequest{Buddy: buddy})
	})

var cmdRename = &command{
	name: "rename", synopsis: "<buddy> [<petname>] [--group GROUP]", summary: "set a buddy's petname and/or group",
	help: `Sets your local name for a buddy. An empty petname ("") clears it.
--group moves the buddy to another group ("" means "Buddies").
`,
	setup: func(fs *flag.FlagSet) runFunc {
		var group *string
		fs.Func("group", `buddy-list group ("" means "Buddies")`, func(s string) error { group = &s; return nil })
		return func(ctx context.Context, cl *cli, args []string) error {
			if err := nargs(args, 1, 2); err != nil {
				return err
			}
			req := &pb.SetBuddyLabelsRequest{Buddy: args[0], Group: group}
			if len(args) == 2 {
				req.Petname = &args[1]
			}
			if req.Petname == nil && req.Group == nil {
				return usageErrorf("give a petname, --group, or both")
			}
			b, err := unary(ctx, cl, rpcSetLabels, req)
			if err != nil {
				return err
			}
			if cl.g.json {
				return cl.emit(b)
			}
			fmt.Fprintf(cl.e.stdout, "%s (%s) is in %s.\n", buddyName(b), clean(b.GetKeyId()), clean(b.GetGroup()))
			return nil
		}
	},
}

// isInviteLink says whether an add argument is an invite link rather than a
// key.
func isInviteLink(s string) bool { return strings.HasPrefix(strings.TrimSpace(s), "openaim:") }

// requestLine describes a pending-in buddy's request, for humans.
func requestLine(b *pb.Buddy) string {
	r := b.GetRequest()
	if r == nil {
		return ""
	}
	var sb strings.Builder
	if r.GetDisplayName() != "" {
		fmt.Fprintf(&sb, "calls themselves %q (unverified)", clean(r.GetDisplayName()))
	} else {
		sb.WriteString("no name given")
	}
	if g := r.GetGreeting(); g != "" {
		fmt.Fprintf(&sb, ": %q", clean(g))
	}
	if r.GetCount() > 1 {
		fmt.Fprintf(&sb, " (asked %d times)", r.GetCount())
	}
	return sb.String()
}
