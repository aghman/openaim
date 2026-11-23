package api

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	pb "github.com/aghman/openaim/internal/apipb"
	"github.com/aghman/openaim/internal/body"
	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/invite"
	wpb "github.com/aghman/openaim/internal/wirepb"
)

// requestFrom seals a BUDDY_REQUEST from id to me, as id's daemon would.
func requestFrom(t *testing.T, id *identity.Identity, me identity.PublicKey, req *wpb.BuddyRequest) [][]byte {
	t.Helper()
	_, b, err := body.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	in := frame.Inner{Type: frame.BuddyRequest, Time: frame.Timestamp(time.Now()), Body: b}
	s, err := frame.SealFirstContact(id, me, frame.LayoutMesh, in.Marshal(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return s.Frames
}

func TestRequestRPCs(t *testing.T) {
	dir, me := initDir(t)
	d, c := start(t, dir)
	ctx := ctxT(t)

	// CreateInvite.
	inv, err := c.CreateInvite(ctx, &pb.CreateInviteRequest{Handle: "Me.Example.com"})
	if err != nil || inv.GetIdentityKey() != me.Public().String() || inv.GetHandle() != "me.example.com" ||
		inv.GetContactHint() != "" || inv.GetNote() == "" || !strings.HasPrefix(inv.GetLink(), invite.Prefix) {
		t.Fatalf("invite %v %v", inv, err)
	}
	_, err = c.CreateInvite(ctx, &pb.CreateInviteRequest{ContactHint: "/ip4/10.0.0.2/tcp/4001"})
	wantCode(t, err, codes.InvalidArgument)
	_, err = c.CreateInvite(ctx, &pb.CreateInviteRequest{Handle: "xn--80ak6aa92e.com"})
	wantCode(t, err, codes.InvalidArgument)

	// AddBuddy by invite link: the request is queued (no transports).
	bob := peer(t, 2)
	link := invite.Invite{Key: bob.Public()}.String()
	b, err := c.AddBuddy(ctx, &pb.AddBuddyRequest{InviteLink: link, Petname: "Bob", Greeting: "hi bob"})
	if err != nil || b.GetState() != pb.BuddyState_BUDDY_STATE_PENDING_OUT || b.GetIdentityKey() != bob.Public().String() ||
		b.GetOutgoingRequest().GetState() != pb.RequestState_REQUEST_STATE_QUEUED || b.GetOutgoingRequest().GetCreatedAt() == nil {
		t.Fatalf("add by invite %v %v", b, err)
	}
	for _, bad := range []*pb.AddBuddyRequest{
		{InviteLink: "openaim:add/nope"},
		{InviteLink: invite.Prefix + peer(t, 3).Public().String() + "?c=%2Fip4%2F192.168.0.9%2Ftcp%2F1"},
		{InviteLink: invite.Prefix + peer(t, 3).Public().String() + "?h=xn--80ak6aa92e.com"},
		{InviteLink: invite.Invite{Key: peer(t, 3).Public()}.String(), IdentityKey: peer(t, 4).Public().String()},
		{IdentityKey: peer(t, 3).Public().String(), Greeting: "\x1b[2J"},
		{IdentityKey: peer(t, 3).Public().String(), Greeting: strings.Repeat("g", 257)},
	} {
		_, err = c.AddBuddy(ctx, bad)
		wantCode(t, err, codes.InvalidArgument)
	}
	_, err = c.AddBuddy(ctx, &pb.AddBuddyRequest{InviteLink: link})
	wantCode(t, err, codes.AlreadyExists)
	_, err = c.AcceptBuddy(ctx, &pb.AcceptBuddyRequest{Buddy: "Bob"})
	wantCode(t, err, codes.FailedPrecondition)
	_, err = c.DeclineBuddy(ctx, &pb.DeclineBuddyRequest{Buddy: "Bob"})
	wantCode(t, err, codes.FailedPrecondition)

	// A request arrives from Carol.
	s, err := c.SubscribeEvents(ctx, &pb.SubscribeEventsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	recv(t, s) // ready
	carol := peer(t, 5)
	rk := peer(t, 6).Public()
	for _, f := range requestFrom(t, carol, me.Public(), &wpb.BuddyRequest{DisplayName: "Carol", Greeting: "remember me?", RecoveryKey: rk[:]}) {
		if _, err := d.Node().HandleFrameFrom(ctx, "test", f); err != nil {
			t.Fatal(err)
		}
	}
	added := recv(t, s).GetBuddyAdded()
	reqEv := recv(t, s).GetBuddyRequest()
	for _, x := range []*pb.Buddy{added, reqEv} {
		if x.GetState() != pb.BuddyState_BUDDY_STATE_PENDING_IN || x.GetRequest().GetDisplayName() != "Carol" ||
			x.GetRequest().GetGreeting() != "remember me?" || x.GetRequest().GetCount() != 1 || x.GetOfferedName() != "Carol" ||
			x.GetRecoveryKey() != rk.String() || x.GetDisplayName() != carol.Public().KeyID() {
			t.Fatalf("event buddy %v", x)
		}
	}
	list, err := c.ListBuddies(ctx, &pb.ListBuddiesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var found *pb.Buddy
	for _, x := range list.GetBuddies() {
		if x.GetIdentityKey() == carol.Public().String() {
			found = x
		}
	}
	if found == nil || !proto.Equal(found.GetRequest(), added.GetRequest()) {
		t.Fatalf("listed %v", found)
	}

	// SetBuddyLabels.
	pet, grp := "Caz", "Old friends"
	lb, err := c.SetBuddyLabels(ctx, &pb.SetBuddyLabelsRequest{Buddy: carol.Public().String(), Petname: &pet, Group: &grp})
	if err != nil || lb.GetPetname() != "Caz" || lb.GetGroup() != "Old friends" || lb.GetDisplayName() != "Caz" {
		t.Fatalf("labels %v %v", lb, err)
	}
	if e := recv(t, s).GetBuddyChanged(); e.GetPetname() != "Caz" {
		t.Fatalf("labels event %v", e)
	}
	lb, err = c.SetBuddyLabels(ctx, &pb.SetBuddyLabelsRequest{Buddy: "Caz", Group: proto.String("")})
	if err != nil || lb.GetPetname() != "Caz" || lb.GetGroup() != "Buddies" {
		t.Fatalf("regroup %v %v", lb, err)
	}
	recv(t, s)
	_, err = c.SetBuddyLabels(ctx, &pb.SetBuddyLabelsRequest{Buddy: "Caz", Petname: proto.String("bell\a")})
	wantCode(t, err, codes.InvalidArgument)
	_, err = c.SetBuddyLabels(ctx, &pb.SetBuddyLabelsRequest{Buddy: "Nobody", Petname: &pet})
	wantCode(t, err, codes.NotFound)

	// AcceptBuddy (the accept stays queued: no transports).
	acc, err := c.AcceptBuddy(ctx, &pb.AcceptBuddyRequest{Buddy: "Caz"})
	if err != nil || acc.GetState() != pb.BuddyState_BUDDY_STATE_ACCEPTED {
		t.Fatalf("accept %v %v", acc, err)
	}
	if e := recv(t, s).GetBuddyChanged(); e.GetState() != pb.BuddyState_BUDDY_STATE_ACCEPTED {
		t.Fatalf("accept event %v", e)
	}
	_, err = c.DeclineBuddy(ctx, &pb.DeclineBuddyRequest{Buddy: "Caz"})
	wantCode(t, err, codes.FailedPrecondition)

	// Dave asks; we decline.
	dave := peer(t, 7)
	for _, f := range requestFrom(t, dave, me.Public(), &wpb.BuddyRequest{DisplayName: "Dave"}) {
		if _, err := d.Node().HandleFrame(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	recv(t, s)
	recv(t, s)
	if _, err := c.DeclineBuddy(ctx, &pb.DeclineBuddyRequest{Buddy: dave.Public().String()}); err != nil {
		t.Fatal(err)
	}
	if e := recv(t, s).GetBuddyRemoved(); e.GetIdentityKey() != dave.Public().String() {
		t.Fatalf("decline event %v", e)
	}
	_, err = c.DeclineBuddy(ctx, &pb.DeclineBuddyRequest{Buddy: dave.Public().String()})
	wantCode(t, err, codes.NotFound)

	// BlockBuddy.
	bl, err := c.BlockBuddy(ctx, &pb.BlockBuddyRequest{Buddy: "Bob"})
	if err != nil || bl.GetState() != pb.BuddyState_BUDDY_STATE_BLOCKED ||
		bl.GetOutgoingRequest().GetState() != pb.RequestState_REQUEST_STATE_FAILED {
		t.Fatalf("block %v %v", bl, err)
	}
	_, err = c.AcceptBuddy(ctx, &pb.AcceptBuddyRequest{Buddy: "Bob"})
	wantCode(t, err, codes.FailedPrecondition)
	st, err := c.GetStatus(ctx, &pb.GetStatusRequest{})
	if err != nil || st.GetBuddies().GetAccepted() != 1 || st.GetBuddies().GetBlocked() != 1 {
		t.Fatalf("status %v %v", st, err)
	}
}
