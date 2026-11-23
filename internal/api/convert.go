package api

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/aghman/openaim/internal/apipb"
	"github.com/aghman/openaim/internal/daemon"
	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/store"
)

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

var buddyStates = map[store.BuddyState]pb.BuddyState{
	store.PendingOut: pb.BuddyState_BUDDY_STATE_PENDING_OUT,
	store.PendingIn:  pb.BuddyState_BUDDY_STATE_PENDING_IN,
	store.Accepted:   pb.BuddyState_BUDDY_STATE_ACCEPTED,
	store.Blocked:    pb.BuddyState_BUDDY_STATE_BLOCKED,
}

var handleStatuses = map[store.HandleStatus]pb.HandleStatus{
	store.HandleVerified:    pb.HandleStatus_HANDLE_STATUS_VERIFIED,
	store.HandleMoved:       pb.HandleStatus_HANDLE_STATUS_MOVED,
	store.HandleUnverified:  pb.HandleStatus_HANDLE_STATUS_UNVERIFIED,
	store.HandleUnreachable: pb.HandleStatus_HANDLE_STATUS_UNREACHABLE,
}

var requestStates = map[store.RequestState]pb.RequestState{
	store.RequestQueued:   pb.RequestState_REQUEST_STATE_QUEUED,
	store.RequestSent:     pb.RequestState_REQUEST_STATE_SENT,
	store.RequestAnswered: pb.RequestState_REQUEST_STATE_ANSWERED,
	store.RequestFailed:   pb.RequestState_REQUEST_STATE_FAILED,
}

// buddyPB converts a buddy with its handle check state and details (either
// nil if none).
func (s *server) buddyPB(b store.Buddy, hc *store.HandleCheck, det *daemon.BuddyDetails) *pb.Buddy {
	out := &pb.Buddy{
		IdentityKey: b.Key.String(),
		KeyId:       b.Key.KeyID(),
		Handle:      b.Handle,
		Petname:     b.Petname,
		Group:       b.Group,
		State:       buddyStates[b.State],
		Verified:    b.Verified,
		AddedAt:     ts(b.AddedAt),
		Presence:    buddyPresencePB(s.n.BuddyPresence(b.Key)),
		DisplayName: s.n.DisplayName(b),
		ShortHandle: s.n.ShortHandle(b.Handle),
	}
	if b.RecoveryKey != nil {
		out.RecoveryKey = b.RecoveryKey.String()
	}
	if det != nil {
		out.OfferedName = det.OfferedName
		if r := det.Request; r != nil {
			out.Request = &pb.BuddyRequestInfo{
				DisplayName: r.DisplayName, Greeting: r.Greeting, FirstReceivedAt: ts(r.FirstAt), LastReceivedAt: ts(r.LastAt),
				Count: uint32(r.Count), SentAt: ts(frame.TimeOf(r.SentTS)),
			}
		}
		if r := det.OutRequest; r != nil {
			out.OutgoingRequest = &pb.OutgoingRequest{
				State: requestStates[r.State], Attempts: uint32(r.Attempts), ContactHint: r.ContactHint,
				LastError: r.LastError, CreatedAt: ts(r.CreatedAt), LastAttemptAt: ts(r.LastAttempt),
			}
		}
	}
	if hc != nil && b.Handle != "" {
		out.HandleStatus = handleStatuses[hc.Status]
		out.HandleLastResult = handleStatuses[hc.LastResult]
		out.HandleCheckedAt = ts(hc.CheckedAt)
		out.HandleNextCheckAt = ts(hc.NextCheck)
		out.HandleError = hc.Error
		if hc.MovedKey != nil && hc.Status == store.HandleMoved {
			out.HandleMovedTo = hc.MovedKey.String()
		}
	}
	return out
}

// buddyWithCheck converts a buddy, loading its handle check state and
// details.
func (s *server) buddyWithCheck(ctx context.Context, b store.Buddy) (*pb.Buddy, error) {
	hc, err := s.n.HandleCheck(ctx, b)
	if err != nil {
		return nil, err
	}
	det, err := s.n.Details(ctx, b)
	if err != nil {
		return nil, err
	}
	return s.buddyPB(b, hc, det), nil
}

var deliveryStates = map[store.OutState]pb.DeliveryState{
	store.Queued: pb.DeliveryState_DELIVERY_STATE_QUEUED,
	store.Acked:  pb.DeliveryState_DELIVERY_STATE_ACKED,
	store.Failed: pb.DeliveryState_DELIVERY_STATE_FAILED,
}

var deliveryPB = map[daemon.DeliveryState]pb.DeliveryState{
	daemon.DeliveryQueued: pb.DeliveryState_DELIVERY_STATE_QUEUED,
	daemon.DeliverySent:   pb.DeliveryState_DELIVERY_STATE_SENT,
	daemon.DeliveryAcked:  pb.DeliveryState_DELIVERY_STATE_ACKED,
	daemon.DeliveryFailed: pb.DeliveryState_DELIVERY_STATE_FAILED,
}

func messagePB(m daemon.Message) *pb.Message {
	out := &pb.Message{
		MsgId:      m.MsgID.String(),
		BuddyKey:   m.Buddy.String(),
		Text:       m.Text,
		SentAt:     ts(m.SentAt),
		ReceivedAt: ts(m.ReceivedAt),
		Seq:        m.Seq,
	}
	switch m.Direction {
	case daemon.Incoming:
		out.Direction = pb.Direction_DIRECTION_INCOMING
	case daemon.Outgoing:
		out.Direction = pb.Direction_DIRECTION_OUTGOING
		out.Delivery = deliveryStates[m.State]
		if m.State == store.Queued && m.Attempts > 0 {
			out.Delivery = pb.DeliveryState_DELIVERY_STATE_SENT
		}
		out.FragCount, out.AckedMask = uint32(m.FragCount), uint32(m.AckedMask)
	}
	return out
}

func messageUpdatePB(u daemon.MessageUpdate) *pb.MessageUpdate {
	return &pb.MessageUpdate{MsgId: u.MsgID.String(), BuddyKey: u.Buddy.String(), Delivery: deliveryPB[u.State],
		AckedMask: uint32(u.AckedMask), FragCount: uint32(u.FragCount), Attempts: uint32(u.Attempts)}
}

func buddyPresencePB(p daemon.BuddyPresence) *pb.Presence {
	return &pb.Presence{State: presenceToPB[p.State], AwayMessage: p.AwayMessage, Since: ts(p.Since),
		IdleMinutes: p.IdleMinutes, Connected: p.Connected}
}

func networkPB(st *daemon.NetworkStatus) *pb.NetworkStatus {
	if st == nil {
		return nil
	}
	out := &pb.NetworkStatus{
		PeerId: st.PeerID.String(), Generation: st.Generation, BootstrapPeers: uint32(st.Bootstrap),
		DhtRoutingTable: uint32(st.DHTPeers), SessionsUp: uint32(st.SessionsUp), Public: st.Public,
		ContactHint: st.ContactHint, BuddiesOnline: uint32(st.Online),
	}
	for _, a := range st.Listen {
		out.ListenAddrs = append(out.ListenAddrs, a.String())
	}
	for _, a := range st.Circuits {
		out.RelayAddrs = append(out.RelayAddrs, a.String())
	}
	for _, r := range st.Relays {
		out.Relays = append(out.Relays, &pb.RelayStatus{PeerId: r.ID.String(), Reserved: r.Reserved,
			LastAttempt: ts(r.LastAttempt), Expires: ts(r.Expires), LastError: r.LastError})
	}
	return out
}

var presenceToPB = map[daemon.PresenceState]pb.PresenceState{
	daemon.Online:  pb.PresenceState_PRESENCE_STATE_ONLINE,
	daemon.Away:    pb.PresenceState_PRESENCE_STATE_AWAY,
	daemon.Offline: pb.PresenceState_PRESENCE_STATE_OFFLINE,
}

var presenceFromPB = map[pb.PresenceState]daemon.PresenceState{
	pb.PresenceState_PRESENCE_STATE_ONLINE:  daemon.Online,
	pb.PresenceState_PRESENCE_STATE_AWAY:    daemon.Away,
	pb.PresenceState_PRESENCE_STATE_OFFLINE: daemon.Offline,
}

func presencePB(p daemon.Presence) *pb.Presence {
	return &pb.Presence{State: presenceToPB[p.State], AwayMessage: p.Away, Since: ts(p.Since)}
}

func (s *server) eventPB(e daemon.Event) *pb.Event {
	out := &pb.Event{Seq: e.Seq, Time: ts(e.Time)}
	switch e.Kind {
	case daemon.EventBuddyAdded:
		out.Kind = &pb.Event_BuddyAdded{BuddyAdded: s.buddyPB(*e.Buddy, e.HandleCheck, e.Details)}
	case daemon.EventBuddyChanged:
		out.Kind = &pb.Event_BuddyChanged{BuddyChanged: s.buddyPB(*e.Buddy, e.HandleCheck, e.Details)}
	case daemon.EventBuddyRemoved:
		out.Kind = &pb.Event_BuddyRemoved{BuddyRemoved: s.buddyPB(*e.Buddy, e.HandleCheck, e.Details)}
	case daemon.EventBuddyHandleWarning:
		out.Kind = &pb.Event_BuddyHandleWarning{BuddyHandleWarning: s.buddyPB(*e.Buddy, e.HandleCheck, e.Details)}
	case daemon.EventBuddyRequest:
		out.Kind = &pb.Event_BuddyRequest{BuddyRequest: s.buddyPB(*e.Buddy, e.HandleCheck, e.Details)}
	case daemon.EventMessageQueued:
		out.Kind = &pb.Event_MessageQueued{MessageQueued: messagePB(*e.Message)}
	case daemon.EventMessageReceived:
		out.Kind = &pb.Event_MessageReceived{MessageReceived: messagePB(*e.Message)}
	case daemon.EventPresenceChanged:
		out.Kind = &pb.Event_PresenceChanged{PresenceChanged: presencePB(*e.Presence)}
	case daemon.EventMessageUpdated:
		out.Kind = &pb.Event_MessageUpdated{MessageUpdated: messageUpdatePB(*e.Update)}
	case daemon.EventBuddyPresence:
		p := *e.BuddyPresence
		b := s.buddyPB(*e.Buddy, e.HandleCheck, e.Details)
		b.Presence = buddyPresencePB(p) // as of the event, not as of now
		out.Kind = &pb.Event_BuddyPresence{BuddyPresence: &pb.BuddyPresence{
			Buddy: b, From: presenceToPB[p.From], To: presenceToPB[p.State], Reason: p.Reason,
			DoorOpen: p.DoorOpen(), DoorClose: p.DoorClose(),
		}}
	default:
		return nil
	}
	return out
}
