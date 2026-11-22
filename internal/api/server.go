package api

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/aghman/openaim/internal/apipb"
	"github.com/aghman/openaim/internal/daemon"
	"github.com/aghman/openaim/internal/store"
)

// defaultHistory is History's limit when the request gives none.
const defaultHistory = 100

// server implements the Daemon service over a node.
type server struct {
	pb.UnimplementedDaemonServer
	n   *daemon.Node
	d   *Daemon
	log *slog.Logger
}

// rpcError maps daemon errors to gRPC status codes.
func (s *server) rpcError(method string, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := status.FromError(err); ok {
		return err
	}
	switch {
	case errors.Is(err, daemon.ErrInvalid), errors.Is(err, daemon.ErrAmbiguous):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, daemon.ErrUnknownBuddy):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, daemon.ErrDuplicate):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, daemon.ErrBlocked), errors.Is(err, daemon.ErrNoHandle), errors.Is(err, daemon.ErrHandleUnverified),
		errors.Is(err, daemon.ErrBackupMismatch):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, daemon.ErrHandleUnreachable):
		return status.Error(codes.Unavailable, err.Error())
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.FromContextError(err).Err()
	}
	s.log.Error("rpc failed", "method", method, "err", err)
	return status.Error(codes.Internal, err.Error())
}

func (s *server) GetStatus(ctx context.Context, _ *pb.GetStatusRequest) (*pb.Status, error) {
	st, err := s.n.Status(ctx)
	if err != nil {
		return nil, s.rpcError("GetStatus", err)
	}
	var rk string
	if k := s.n.RecoveryKey(); k != nil {
		rk = k.String()
	}
	return &pb.Status{
		RecoveryKey: rk,
		IdentityKey: st.Identity.String(),
		KeyId:       st.Identity.KeyID(),
		Version:     daemon.BuildVersion(),
		StartedAt:   timestamppb.New(st.Started),
		Uptime:      durationpb.New(s.n.Now().Sub(st.Started)),
		Buddies: &pb.BuddyCounts{
			Total:      uint32(st.TotalBuddies),
			PendingOut: uint32(st.Buddies[store.PendingOut]),
			PendingIn:  uint32(st.Buddies[store.PendingIn]),
			Accepted:   uint32(st.Buddies[store.Accepted]),
			Blocked:    uint32(st.Buddies[store.Blocked]),
		},
		Presence:       presencePB(st.Presence),
		QueuedMessages: uint32(st.QueuedMessages),
		DataDir:        s.n.Paths().Dir,
	}, nil
}

func (s *server) ListBuddies(ctx context.Context, _ *pb.ListBuddiesRequest) (*pb.ListBuddiesResponse, error) {
	bs, err := s.n.Buddies(ctx)
	if err != nil {
		return nil, s.rpcError("ListBuddies", err)
	}
	checks, err := s.n.HandleChecks(ctx)
	if err != nil {
		return nil, s.rpcError("ListBuddies", err)
	}
	out := &pb.ListBuddiesResponse{Buddies: make([]*pb.Buddy, len(bs))}
	for i, b := range bs {
		var hc *store.HandleCheck
		if c, ok := checks[b.ID]; ok {
			hc = &c
		}
		out.Buddies[i] = s.buddyPB(b, hc)
	}
	return out, nil
}

func (s *server) AddBuddy(ctx context.Context, req *pb.AddBuddyRequest) (*pb.Buddy, error) {
	a, err := s.n.AddBuddyWith(ctx, daemon.AddBuddyOptions{
		Key: req.GetIdentityKey(), Handle: req.GetHandle(), Petname: req.GetPetname(), Group: req.GetGroup(),
	})
	if err != nil {
		return nil, s.rpcError("AddBuddy", err)
	}
	out := s.buddyPB(a.Buddy, a.Check)
	if a.HandleDropped != nil {
		out.HandleError = a.HandleDropped.Error()
	}
	return out, nil
}

func (s *server) CheckHandle(ctx context.Context, req *pb.CheckHandleRequest) (*pb.CheckHandleResponse, error) {
	r, err := s.n.CheckHandle(ctx, req.GetBuddy())
	if err != nil {
		return nil, s.rpcError("CheckHandle", err)
	}
	return &pb.CheckHandleResponse{Buddy: s.buddyPB(r.Buddy, &r.Check), Result: handleStatuses[r.Result]}, nil
}

func (s *server) RemoveBuddy(ctx context.Context, req *pb.RemoveBuddyRequest) (*pb.RemoveBuddyResponse, error) {
	if _, err := s.n.RemoveBuddy(ctx, req.GetBuddy()); err != nil {
		return nil, s.rpcError("RemoveBuddy", err)
	}
	return &pb.RemoveBuddyResponse{}, nil
}

func (s *server) SetBuddyVerified(ctx context.Context, req *pb.SetBuddyVerifiedRequest) (*pb.Buddy, error) {
	b, err := s.n.SetBuddyVerified(ctx, req.GetBuddy(), req.GetVerified())
	if err != nil {
		return nil, s.rpcError("SetBuddyVerified", err)
	}
	out, err := s.buddyWithCheck(ctx, b)
	return out, s.rpcError("SetBuddyVerified", err)
}

func (s *server) GetSafetyNumber(ctx context.Context, req *pb.GetSafetyNumberRequest) (*pb.SafetyNumber, error) {
	sn, b, err := s.n.SafetyNumber(ctx, req.GetBuddy())
	if err != nil {
		return nil, s.rpcError("GetSafetyNumber", err)
	}
	out, err := s.buddyWithCheck(ctx, b)
	if err != nil {
		return nil, s.rpcError("GetSafetyNumber", err)
	}
	return &pb.SafetyNumber{SafetyNumber: sn, Buddy: out}, nil
}

func (s *server) SendIM(ctx context.Context, req *pb.SendIMRequest) (*pb.SendIMResponse, error) {
	m, err := s.n.SendIM(ctx, req.GetBuddy(), req.GetText())
	if err != nil {
		return nil, s.rpcError("SendIM", err)
	}
	return &pb.SendIMResponse{MsgId: m.MsgID.String(), Message: messagePB(m)}, nil
}

func (s *server) History(ctx context.Context, req *pb.HistoryRequest) (*pb.HistoryResponse, error) {
	limit := int(req.GetLimit())
	if limit == 0 {
		limit = defaultHistory
	}
	ms, err := s.n.History(ctx, req.GetBuddy(), limit)
	if err != nil {
		return nil, s.rpcError("History", err)
	}
	out := &pb.HistoryResponse{Messages: make([]*pb.Message, len(ms))}
	for i, m := range ms {
		out.Messages[i] = messagePB(m)
	}
	return out, nil
}

func (s *server) SetPresence(ctx context.Context, req *pb.SetPresenceRequest) (*pb.Presence, error) {
	st, ok := presenceFromPB[req.GetState()]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "presence state %v", req.GetState())
	}
	p, err := s.n.SetPresence(ctx, st, req.GetAwayMessage())
	if err != nil {
		return nil, s.rpcError("SetPresence", err)
	}
	return presencePB(p), nil
}

func (s *server) SubscribeEvents(_ *pb.SubscribeEventsRequest, stream grpc.ServerStreamingServer[pb.Event]) error {
	sub := s.n.Subscribe()
	defer sub.Close()
	ready := &pb.Event{Seq: sub.Seq, Time: timestamppb.New(s.n.Now()), Kind: &pb.Event_Ready{Ready: &pb.Ready{}}}
	if err := stream.Send(ready); err != nil {
		return err
	}
	for {
		select {
		case e, ok := <-sub.C:
			if !ok {
				switch err := sub.Err(); {
				case errors.Is(err, daemon.ErrLagged):
					return status.Error(codes.ResourceExhausted, "event subscriber fell behind; resubscribe and reload state")
				case errors.Is(err, daemon.ErrClosed):
					return status.Error(codes.Unavailable, "daemon is shutting down")
				default:
					return nil
				}
			}
			if pe := s.eventPB(e); pe != nil {
				if err := stream.Send(pe); err != nil {
					return err
				}
			}
		case <-s.d.stopping:
			return status.Error(codes.Unavailable, "daemon is shutting down")
		case <-stream.Context().Done():
			return status.FromContextError(stream.Context().Err()).Err()
		}
	}
}

func (s *server) ExportBackup(ctx context.Context, req *pb.ExportBackupRequest) (*pb.ExportBackupResponse, error) {
	b, err := s.n.ExportBackupWith(ctx, daemon.ExportBackupOptions{
		Passphrase: req.GetPassphrase(), Previous: req.GetPreviousBackup(), PreviousPassphrase: req.GetPreviousPassphrase(),
	})
	if err != nil {
		return nil, s.rpcError("ExportBackup", err)
	}
	out := &pb.ExportBackupResponse{Backup: b.Blob, IncludesRecoveryKey: b.IncludesRecovery}
	if b.RecoveryKey != nil {
		out.RecoveryKey = b.RecoveryKey.String()
	}
	if req.GetIncludeRecoveryPhrase() {
		out.RecoveryPhrase = s.n.RecoveryPhrase()
	}
	s.log.Info("backup exported", "bytes", len(b.Blob), "with_phrase", req.GetIncludeRecoveryPhrase(),
		"with_recovery_key", b.IncludesRecovery)
	return out, nil
}

func (s *server) Shutdown(context.Context, *pb.ShutdownRequest) (*pb.ShutdownResponse, error) {
	s.log.Info("shutdown requested over the API")
	s.d.requestStop()
	return &pb.ShutdownResponse{}, nil
}

// logUnary logs each call at debug level, and failures at warn.
func logUnary(log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := h(ctx, req)
		code := status.Code(err)
		lvl := slog.LevelDebug
		if code != codes.OK && code != codes.InvalidArgument && code != codes.NotFound && code != codes.AlreadyExists {
			lvl = slog.LevelWarn
		}
		log.Log(ctx, lvl, "rpc", "method", info.FullMethod, "code", code.String(), "took", time.Since(start))
		return resp, err
	}
}
