package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	pb "github.com/aghman/openaim/internal/apipb"
	"github.com/aghman/openaim/internal/daemon"
)

// unary runs one RPC with the timeout and maps its error.
func unary[Req, Resp any](ctx context.Context, cl *cli, f func(pb.DaemonClient, context.Context, Req) (Resp, error), req Req) (Resp, error) {
	var zero Resp
	c, err := cl.client()
	if err != nil {
		return zero, err
	}
	cctx, cancel := cl.call(ctx)
	defer cancel()
	resp, err := f(c, cctx, req)
	if err != nil {
		return zero, cl.rpcErr(err)
	}
	return resp, nil
}

// Method values on the client interface, for unary.
var (
	rpcGetStatus = func(c pb.DaemonClient, ctx context.Context, r *pb.GetStatusRequest) (*pb.Status, error) {
		return c.GetStatus(ctx, r)
	}
	rpcListBuddies = func(c pb.DaemonClient, ctx context.Context, r *pb.ListBuddiesRequest) (*pb.ListBuddiesResponse, error) {
		return c.ListBuddies(ctx, r)
	}
	rpcAddBuddy = func(c pb.DaemonClient, ctx context.Context, r *pb.AddBuddyRequest) (*pb.Buddy, error) {
		return c.AddBuddy(ctx, r)
	}
	rpcRemoveBuddy = func(c pb.DaemonClient, ctx context.Context, r *pb.RemoveBuddyRequest) (*pb.RemoveBuddyResponse, error) {
		return c.RemoveBuddy(ctx, r)
	}
	rpcSetVerified = func(c pb.DaemonClient, ctx context.Context, r *pb.SetBuddyVerifiedRequest) (*pb.Buddy, error) {
		return c.SetBuddyVerified(ctx, r)
	}
	rpcSafetyNumber = func(c pb.DaemonClient, ctx context.Context, r *pb.GetSafetyNumberRequest) (*pb.SafetyNumber, error) {
		return c.GetSafetyNumber(ctx, r)
	}
	rpcSendIM = func(c pb.DaemonClient, ctx context.Context, r *pb.SendIMRequest) (*pb.SendIMResponse, error) {
		return c.SendIM(ctx, r)
	}
	rpcHistory = func(c pb.DaemonClient, ctx context.Context, r *pb.HistoryRequest) (*pb.HistoryResponse, error) {
		return c.History(ctx, r)
	}
	rpcSetPresence = func(c pb.DaemonClient, ctx context.Context, r *pb.SetPresenceRequest) (*pb.Presence, error) {
		return c.SetPresence(ctx, r)
	}
	rpcExportBackup = func(c pb.DaemonClient, ctx context.Context, r *pb.ExportBackupRequest) (*pb.ExportBackupResponse, error) {
		return c.ExportBackup(ctx, r)
	}
	rpcShutdown = func(c pb.DaemonClient, ctx context.Context, r *pb.ShutdownRequest) (*pb.ShutdownResponse, error) {
		return c.Shutdown(ctx, r)
	}
)

// ---- status

var cmdStatus = &command{
	name: "status", synopsis: "[--verbose]", summary: "show our identity, presence and counts",
	help: `Prints the identity key and key ID, presence, buddy count and queued
messages. --verbose adds everything else the daemon reports: version, data
dir, start time, uptime and the buddy counts by state.
`,
	setup: func(fs *flag.FlagSet) runFunc {
		verbose := fs.Bool("verbose", false, "show everything the daemon reports")
		fs.BoolVar(verbose, "v", false, "short for --verbose")
		return func(ctx context.Context, cl *cli, args []string) error {
			if err := nargs(args, 0, 0); err != nil {
				return err
			}
			st, err := unary(ctx, cl, rpcGetStatus, &pb.GetStatusRequest{})
			if err != nil {
				return err
			}
			if cl.g.json {
				return cl.emit(st)
			}
			s := cl.style()
			t := &table{}
			label := func(l string) cell { return cell{text: l, color: bold} }
			t.row(label("Identity"), cell{text: clean(st.GetKeyId()) + "  " + clean(st.GetIdentityKey())})
			t.row(label("Presence"), cell{text: presenceText(st.GetPresence())})
			bc := st.GetBuddies()
			t.row(label("Buddies"), cell{text: fmt.Sprint(bc.GetTotal())})
			t.row(label("Queued"), cell{text: fmt.Sprintf("%d message(s)", st.GetQueuedMessages())})
			if *verbose {
				t.row(label("By state"), cell{text: fmt.Sprintf("%d accepted, %d pending-out, %d pending-in, %d blocked",
					bc.GetAccepted(), bc.GetPendingOut(), bc.GetPendingIn(), bc.GetBlocked())})
				t.row(label("Since"), cell{text: fmtTime(st.GetPresence().GetSince())})
				t.row(label("Version"), cell{text: clean(st.GetVersion())})
				t.row(label("Data dir"), cell{text: clean(st.GetDataDir())})
				t.row(label("Started"), cell{text: fmtTime(st.GetStartedAt())})
				t.row(label("Uptime"), cell{text: fmtDuration(st.GetUptime())})
			}
			t.write(cl.e.stdout, s)
			return nil
		}
	},
}

// ---- buddies

var cmdBuddies = &command{
	name: "buddies", summary: "list buddies by group",
	help: `Columns: group, name (petname, else handle, else key ID), handle if any
buddy has one, key ID, state, whether you verified the safety number, and
presence. Unverified buddies are marked; compare with "openaim verify".
`,
	setup: func(*flag.FlagSet) runFunc {
		return func(ctx context.Context, cl *cli, args []string) error {
			if err := nargs(args, 0, 0); err != nil {
				return err
			}
			list, err := unary(ctx, cl, rpcListBuddies, &pb.ListBuddiesRequest{})
			if err != nil {
				return err
			}
			if cl.g.json {
				return cl.emit(list)
			}
			bs := list.GetBuddies()
			if len(bs) == 0 {
				fmt.Fprintln(cl.e.stdout, "No buddies yet. Add one with: openaim add <identity-key>")
				return nil
			}
			handles := false
			for _, b := range bs {
				handles = handles || b.GetHandle() != ""
			}
			t := &table{}
			head := []cell{{text: "GROUP"}, {text: "NAME"}}
			if handles {
				head = append(head, cell{text: "HANDLE"})
			}
			head = append(head, cell{text: "KEY ID"}, cell{text: "STATE"}, cell{text: "VERIFIED"}, cell{text: "PRESENCE"})
			for i := range head {
				head[i].color = bold
			}
			t.row(head...)
			prevGroup := ""
			for i, b := range bs {
				group := clean(b.GetGroup())
				gc := cell{text: group, color: bold}
				if i > 0 && group == prevGroup {
					gc = cell{}
				}
				prevGroup = group
				row := []cell{gc, {text: buddyName(b)}}
				if handles {
					h := clean(b.GetHandle())
					if h == "" {
						h = "-"
					}
					row = append(row, cell{text: h})
				}
				verified := cell{text: "unverified", color: yellow}
				if b.GetVerified() {
					verified = cell{text: "✓", color: green}
				}
				state := cell{text: buddyStateName(b.GetState())}
				if b.GetState() == pb.BuddyState_BUDDY_STATE_BLOCKED {
					state.color = red
				}
				row = append(row, cell{text: clean(b.GetKeyId())}, state, verified,
					cell{text: presenceName(b.GetPresence().GetState()), color: dimIfOffline(b.GetPresence())})
				t.row(row...)
			}
			t.write(cl.e.stdout, cl.style())
			return nil
		}
	},
}

func dimIfOffline(p *pb.Presence) string {
	if p.GetState() == pb.PresenceState_PRESENCE_STATE_OFFLINE {
		return dim
	}
	return ""
}

// ---- add

var cmdAdd = &command{
	name: "add", synopsis: "<identity-key> [--petname NAME] [--group GROUP]", summary: "add a buddy by identity key",
	help: `The identity key is the base32 key from an invite link. The buddy starts
as pending-out until they accept. Exits 5 if the buddy is already on the
list.
`,
	setup: func(fs *flag.FlagSet) runFunc {
		petname := fs.String("petname", "", "your local name for the buddy")
		group := fs.String("group", "", `buddy-list group (default "Buddies")`)
		return func(ctx context.Context, cl *cli, args []string) error {
			if err := nargs(args, 1, 1); err != nil {
				return err
			}
			b, err := unary(ctx, cl, rpcAddBuddy, &pb.AddBuddyRequest{IdentityKey: args[0], Petname: *petname, Group: *group})
			if err != nil {
				return err
			}
			if cl.g.json {
				return cl.emit(b)
			}
			fmt.Fprintf(cl.e.stdout, "Added %s (%s) to %s; %s.\n", buddyName(b), clean(b.GetKeyId()), clean(b.GetGroup()), buddyStateName(b.GetState()))
			fmt.Fprintf(cl.e.stdout, "Compare safety numbers with: openaim verify %s\n", clean(b.GetKeyId()))
			return nil
		}
	},
}

// ---- remove

var cmdRemove = &command{
	name: "remove", synopsis: "<buddy>", summary: "remove a buddy with its queued messages and history",
	setup: func(*flag.FlagSet) runFunc {
		return func(ctx context.Context, cl *cli, args []string) error {
			if err := nargs(args, 1, 1); err != nil {
				return err
			}
			if _, err := unary(ctx, cl, rpcRemoveBuddy, &pb.RemoveBuddyRequest{Buddy: args[0]}); err != nil {
				return err
			}
			if cl.g.json {
				return cl.emit(map[string]any{"removed": args[0]})
			}
			fmt.Fprintf(cl.e.stdout, "Removed %s.\n", clean(args[0]))
			return nil
		}
	},
}

// ---- verify

var cmdVerify = &command{
	name: "verify", synopsis: "<buddy> [--confirm | --unverify]", summary: "show a buddy's safety number; --confirm marks it verified",
	help: `The safety number is the same on both sides. Compare it with your buddy
in person or over a call you trust; if it matches, run verify again with
--confirm to mark the buddy verified. --unverify clears the mark.
`,
	setup: func(fs *flag.FlagSet) runFunc {
		confirm := fs.Bool("confirm", false, "mark the buddy verified (after comparing the numbers)")
		unverify := fs.Bool("unverify", false, "clear the verified mark")
		return func(ctx context.Context, cl *cli, args []string) error {
			if err := nargs(args, 1, 1); err != nil {
				return err
			}
			if *confirm && *unverify {
				return usageErrorf("--confirm and --unverify conflict")
			}
			sn, err := unary(ctx, cl, rpcSafetyNumber, &pb.GetSafetyNumberRequest{Buddy: args[0]})
			if err != nil {
				return err
			}
			if *confirm || *unverify {
				// By identity key, so the mark lands on the buddy whose number was shown.
				b, err := unary(ctx, cl, rpcSetVerified, &pb.SetBuddyVerifiedRequest{Buddy: sn.GetBuddy().GetIdentityKey(), Verified: *confirm})
				if err != nil {
					return err
				}
				sn.Buddy = b
			}
			if cl.g.json {
				return cl.emit(sn)
			}
			b := sn.GetBuddy()
			s := cl.style()
			w := cl.e.stdout
			fmt.Fprintf(w, "Safety number with %s (%s):\n\n", buddyName(b), clean(b.GetKeyId()))
			for _, line := range safetyGroups(sn.GetSafetyNumber()) {
				fmt.Fprintf(w, "    %s\n", s.paint(bold, line))
			}
			fmt.Fprintln(w)
			switch {
			case *confirm:
				fmt.Fprintf(w, "%s is now %s.\n", buddyName(b), s.paint(green, "verified"))
			case *unverify:
				fmt.Fprintf(w, "%s is now %s.\n", buddyName(b), s.paint(yellow, "unverified"))
			case b.GetVerified():
				fmt.Fprintf(w, "%s is %s.\n", buddyName(b), s.paint(green, "verified"))
			default:
				fmt.Fprintf(w, "%s is %s. If the number matches theirs, run:\n  openaim verify %s --confirm\n",
					buddyName(b), s.paint(yellow, "unverified"), clean(b.GetKeyId()))
			}
			return nil
		}
	},
}

// ---- send

// maxStdinText bounds what send reads from stdin; the daemon enforces the
// real (much smaller) limit.
const maxStdinText = 64 << 10

var cmdSend = &command{
	name: "send", synopsis: "<buddy> <text...> | <buddy> -", summary: "send an IM; prints its msg_id",
	noIntersperse: true,
	help: `The words after the buddy are joined with spaces. With "-" the text is
read from stdin (one trailing newline is dropped). Flags must come before
the buddy; everything after it is text.
`,
	setup: func(*flag.FlagSet) runFunc {
		return func(ctx context.Context, cl *cli, args []string) error {
			if err := nargs(args, 2, -1); err != nil {
				if len(args) == 1 {
					return usageErrorf("no message text")
				}
				return err
			}
			text := strings.Join(args[1:], " ")
			if len(args) == 2 && args[1] == "-" {
				b, err := io.ReadAll(io.LimitReader(cl.e.stdin, maxStdinText+1))
				if err != nil {
					return fmt.Errorf("reading stdin: %w", err)
				}
				if len(b) > maxStdinText {
					return fmt.Errorf("message on stdin is over %d bytes", maxStdinText)
				}
				text = strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
			}
			if text == "" {
				return usageErrorf("no message text")
			}
			r, err := unary(ctx, cl, rpcSendIM, &pb.SendIMRequest{Buddy: args[0], Text: text})
			if err != nil {
				return err
			}
			if cl.g.json {
				return cl.emit(r)
			}
			fmt.Fprintln(cl.e.stdout, clean(r.GetMsgId()))
			return nil
		}
	},
}

// ---- history

var cmdHistory = &command{
	name: "history", synopsis: "<buddy> [--limit N]", summary: "show recent IMs with a buddy, oldest first",
	setup: func(fs *flag.FlagSet) runFunc {
		limit := fs.Uint("limit", 0, "most recent messages to show (default 100, max 1000)")
		return func(ctx context.Context, cl *cli, args []string) error {
			if err := nargs(args, 1, 1); err != nil {
				return err
			}
			if *limit > 1<<31 {
				return usageErrorf("--limit %d is too large", *limit)
			}
			h, err := unary(ctx, cl, rpcHistory, &pb.HistoryRequest{Buddy: args[0], Limit: uint32(*limit)})
			if err != nil {
				return err
			}
			if cl.g.json {
				return cl.emit(h)
			}
			if len(h.GetMessages()) == 0 {
				fmt.Fprintf(cl.e.stdout, "No messages with %s.\n", clean(args[0]))
				return nil
			}
			names, err := cl.buddyNames(ctx)
			if err != nil {
				return err
			}
			s := cl.style()
			for _, m := range h.GetMessages() {
				fmt.Fprintln(cl.e.stdout, formatMessage(s, m, names))
			}
			return nil
		}
	},
}

// buddyNames maps identity keys to display names, for showing messages.
func (cl *cli) buddyNames(ctx context.Context) (map[string]string, error) {
	list, err := unary(ctx, cl, rpcListBuddies, &pb.ListBuddiesRequest{})
	if err != nil {
		return nil, err
	}
	names := make(map[string]string, len(list.GetBuddies()))
	for _, b := range list.GetBuddies() {
		names[b.GetIdentityKey()] = buddyName(b)
	}
	return names, nil
}

func nameFor(names map[string]string, key string) string {
	if n, ok := names[key]; ok {
		return n
	}
	if len(key) > 8 {
		key = key[:8] + "…"
	}
	return clean(key)
}

// formatMessage is one IM line: "[time] who: text", plus the delivery
// state of outgoing messages.
func formatMessage(s style, m *pb.Message, names map[string]string) string {
	who := nameFor(names, m.GetBuddyKey())
	color := ""
	suffix := ""
	if m.GetDirection() == pb.Direction_DIRECTION_OUTGOING {
		who, color = "me", dim
		if d := deliveryName(m.GetDelivery()); d != "" {
			suffix = "  " + s.paint(dim, "["+d+"]")
		}
	}
	prefix := "[" + fmtTime(m.GetSentAt()) + "] "
	indent := strings.Repeat(" ", displayWidth(prefix)+displayWidth(who)+2)
	return s.paint(dim, prefix) + s.paint(withBold(color), who) + ": " + cleanText(m.GetText(), indent) + suffix
}

func withBold(c string) string {
	if c == "" {
		return bold
	}
	return c
}

// ---- away / back

var cmdAway = &command{
	name: "away", synopsis: "[message...]", summary: "set yourself away, with an optional away message",
	help: `The words are joined with spaces. %n, %d and %t in the message become the
buddy's name, the date and the time when it is sent. The presence persists
across daemon restarts.
`,
	noIntersperse: true,
	setup: func(*flag.FlagSet) runFunc {
		return func(ctx context.Context, cl *cli, args []string) error {
			return cl.setPresence(ctx, pb.PresenceState_PRESENCE_STATE_AWAY, strings.Join(args, " "))
		}
	},
}

var cmdBack = &command{
	name: "back", summary: "come back from away (online, away message cleared)",
	setup: func(*flag.FlagSet) runFunc {
		return func(ctx context.Context, cl *cli, args []string) error {
			if err := nargs(args, 0, 0); err != nil {
				return err
			}
			return cl.setPresence(ctx, pb.PresenceState_PRESENCE_STATE_ONLINE, "")
		}
	},
}

func (cl *cli) setPresence(ctx context.Context, state pb.PresenceState, msg string) error {
	p, err := unary(ctx, cl, rpcSetPresence, &pb.SetPresenceRequest{State: state, AwayMessage: msg})
	if err != nil {
		return err
	}
	if cl.g.json {
		return cl.emit(p)
	}
	fmt.Fprintf(cl.e.stdout, "Presence: %s\n", presenceText(p))
	return nil
}

// ---- shutdown

var cmdShutdown = &command{
	name: "shutdown", summary: "stop the daemon gracefully",
	setup: func(*flag.FlagSet) runFunc {
		return func(ctx context.Context, cl *cli, args []string) error {
			if err := nargs(args, 0, 0); err != nil {
				return err
			}
			if _, err := unary(ctx, cl, rpcShutdown, &pb.ShutdownRequest{}); err != nil {
				return err
			}
			if cl.g.json {
				return cl.emit(map[string]any{"shutting_down": true})
			}
			fmt.Fprintln(cl.e.stdout, "openaimd is shutting down.")
			return nil
		}
	},
}

// ---- version

var cmdVersion = &command{
	name: "version", summary: "print the client version, and the daemon's if it is running",
	setup: func(*flag.FlagSet) runFunc {
		return func(ctx context.Context, cl *cli, args []string) error {
			if err := nargs(args, 0, 0); err != nil {
				return err
			}
			client := daemon.BuildVersion()
			// The daemon is optional here: ask briefly, and don't fail.
			short := *cl
			short.g.timeout = min(cl.g.timeout, 2*time.Second)
			if short.g.timeout <= 0 {
				short.g.timeout = 2 * time.Second
			}
			dv := ""
			st, err := unary(ctx, &short, rpcGetStatus, &pb.GetStatusRequest{})
			cl.conn = short.conn
			if err == nil {
				dv = st.GetVersion()
			}
			var nr *cliError
			notRunning := errors.As(err, &nr) && nr.code == exitNotRunning
			if cl.g.json {
				obj := map[string]any{"client": client}
				if err == nil {
					obj["daemon"] = dv
				}
				return cl.emit(obj)
			}
			fmt.Fprintln(cl.e.stdout, "openaim", client)
			switch {
			case err == nil:
				fmt.Fprintln(cl.e.stdout, "openaimd", clean(dv))
			case notRunning:
				fmt.Fprintln(cl.e.stdout, "openaimd not running")
			default:
				fmt.Fprintln(cl.e.stdout, "openaimd unknown:", clean(err.Error()))
			}
			return nil
		}
	},
}
