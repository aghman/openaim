package api

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/aghman/openaim/internal/apipb"
	"github.com/aghman/openaim/internal/daemon"
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

// buddyPB converts a buddy with its handle check state (nil if none).
func (s *server) buddyPB(b store.Buddy, hc *store.HandleCheck) *pb.Buddy {
	out := &pb.Buddy{
		IdentityKey: b.Key.String(),
		KeyId:       b.Key.KeyID(),
		Handle:      b.Handle,
		Petname:     b.Petname,
		Group:       b.Group,
		State:       buddyStates[b.State],
		Verified:    b.Verified,
		AddedAt:     ts(b.AddedAt),
		// TODO(presence): the buddy's last-heard presence, once received.
		Presence:    &pb.Presence{State: pb.PresenceState_PRESENCE_STATE_OFFLINE},
		DisplayName: s.n.DisplayName(b),
		ShortHandle: s.n.ShortHandle(b.Handle),
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

// buddyWithCheck converts a buddy, loading its handle check state.
func (s *server) buddyWithCheck(ctx context.Context, b store.Buddy) (*pb.Buddy, error) {
	hc, err := s.n.HandleCheck(ctx, b)
	if err != nil {
		return nil, err
	}
	return s.buddyPB(b, hc), nil
}

var deliveryStates = map[store.OutState]pb.DeliveryState{
	store.Queued: pb.DeliveryState_DELIVERY_STATE_QUEUED,
	store.Acked:  pb.DeliveryState_DELIVERY_STATE_ACKED,
	store.Failed: pb.DeliveryState_DELIVERY_STATE_FAILED,
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
		out.Kind = &pb.Event_BuddyAdded{BuddyAdded: s.buddyPB(*e.Buddy, e.HandleCheck)}
	case daemon.EventBuddyChanged:
		out.Kind = &pb.Event_BuddyChanged{BuddyChanged: s.buddyPB(*e.Buddy, e.HandleCheck)}
	case daemon.EventBuddyRemoved:
		out.Kind = &pb.Event_BuddyRemoved{BuddyRemoved: s.buddyPB(*e.Buddy, e.HandleCheck)}
	case daemon.EventBuddyHandleWarning:
		out.Kind = &pb.Event_BuddyHandleWarning{BuddyHandleWarning: s.buddyPB(*e.Buddy, e.HandleCheck)}
	case daemon.EventMessageQueued:
		out.Kind = &pb.Event_MessageQueued{MessageQueued: messagePB(*e.Message)}
	case daemon.EventMessageReceived:
		out.Kind = &pb.Event_MessageReceived{MessageReceived: messagePB(*e.Message)}
	case daemon.EventPresenceChanged:
		out.Kind = &pb.Event_PresenceChanged{PresenceChanged: presencePB(*e.Presence)}
	default:
		return nil
	}
	return out
}
