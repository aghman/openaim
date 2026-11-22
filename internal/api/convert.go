package api

import (
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

func buddyPB(b store.Buddy) *pb.Buddy {
	return &pb.Buddy{
		IdentityKey: b.Key.String(),
		KeyId:       b.Key.KeyID(),
		Handle:      b.Handle,
		Petname:     b.Petname,
		Group:       b.Group,
		State:       buddyStates[b.State],
		Verified:    b.Verified,
		AddedAt:     ts(b.AddedAt),
		// TODO(presence): the buddy's last-heard presence, once received.
		Presence: &pb.Presence{State: pb.PresenceState_PRESENCE_STATE_OFFLINE},
	}
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

func eventPB(e daemon.Event) *pb.Event {
	out := &pb.Event{Seq: e.Seq, Time: ts(e.Time)}
	switch e.Kind {
	case daemon.EventBuddyAdded:
		out.Kind = &pb.Event_BuddyAdded{BuddyAdded: buddyPB(*e.Buddy)}
	case daemon.EventBuddyChanged:
		out.Kind = &pb.Event_BuddyChanged{BuddyChanged: buddyPB(*e.Buddy)}
	case daemon.EventBuddyRemoved:
		out.Kind = &pb.Event_BuddyRemoved{BuddyRemoved: buddyPB(*e.Buddy)}
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
