package tui

import (
	"context"
	"errors"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aghman/openaim/internal/api"
	pb "github.com/aghman/openaim/internal/apipb"
)

// Client is the part of the daemon API (proto/openaim/api/v1) the TUI uses.
// Buddies are always named by identity key, so a selector never matches
// more than one. Implementations must be safe for concurrent use: calls run
// in Bubble Tea commands, off the UI goroutine.
type Client interface {
	GetStatus(ctx context.Context) (*pb.Status, error)
	ListBuddies(ctx context.Context) ([]*pb.Buddy, error)
	AddBuddy(ctx context.Context, req *pb.AddBuddyRequest) (*pb.Buddy, error)
	RemoveBuddy(ctx context.Context, buddy string) error
	SetBuddyVerified(ctx context.Context, buddy string, verified bool) (*pb.Buddy, error)
	GetSafetyNumber(ctx context.Context, buddy string) (*pb.SafetyNumber, error)
	SendIM(ctx context.Context, buddy, text string) (*pb.SendIMResponse, error)
	History(ctx context.Context, buddy string, limit uint32) ([]*pb.Message, error)
	SetPresence(ctx context.Context, state pb.PresenceState, away string) (*pb.Presence, error)
	// Subscribe opens the event stream. Its first event is always ready.
	// Canceling ctx ends the stream.
	Subscribe(ctx context.Context) (EventStream, error)
	// Close releases the connection. Calls in flight fail.
	Close() error
}

// EventStream is a live SubscribeEvents stream.
type EventStream interface {
	Recv() (*pb.Event, error)
}

// Connector opens a Client. It is called again for every reconnect.
type Connector func(ctx context.Context) (Client, error)

// NotRunningError means no daemon answers: the socket is missing, or
// nothing listens on it.
type NotRunningError struct {
	Socket string
	Reason string // e.g. "no socket at …"
}

func (e *NotRunningError) Error() string { return "openaimd is not running (" + e.Reason + ")" }

// IsNotRunning reports whether err says the daemon isn't running.
func IsNotRunning(err error) bool {
	var nr *NotRunningError
	if errors.As(err, &nr) {
		return true
	}
	return status.Code(err) == codes.Unavailable
}

// DialSocket is a Connector for the daemon API on a Unix socket.
func DialSocket(socket string) Connector {
	return func(ctx context.Context) (Client, error) {
		if _, err := os.Stat(socket); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, &NotRunningError{Socket: socket, Reason: "no socket at " + socket}
			}
			return nil, err
		}
		conn, err := api.Dial(socket)
		if err != nil {
			return nil, err
		}
		return &grpcClient{conn: conn, c: pb.NewDaemonClient(conn)}, nil
	}
}

// grpcClient is a Client over a gRPC connection.
type grpcClient struct {
	conn *grpc.ClientConn
	c    pb.DaemonClient
}

func (g *grpcClient) GetStatus(ctx context.Context) (*pb.Status, error) {
	return g.c.GetStatus(ctx, &pb.GetStatusRequest{})
}

func (g *grpcClient) ListBuddies(ctx context.Context) ([]*pb.Buddy, error) {
	r, err := g.c.ListBuddies(ctx, &pb.ListBuddiesRequest{})
	return r.GetBuddies(), err
}

func (g *grpcClient) AddBuddy(ctx context.Context, req *pb.AddBuddyRequest) (*pb.Buddy, error) {
	return g.c.AddBuddy(ctx, req)
}

func (g *grpcClient) RemoveBuddy(ctx context.Context, buddy string) error {
	_, err := g.c.RemoveBuddy(ctx, &pb.RemoveBuddyRequest{Buddy: buddy})
	return err
}

func (g *grpcClient) SetBuddyVerified(ctx context.Context, buddy string, verified bool) (*pb.Buddy, error) {
	return g.c.SetBuddyVerified(ctx, &pb.SetBuddyVerifiedRequest{Buddy: buddy, Verified: verified})
}

func (g *grpcClient) GetSafetyNumber(ctx context.Context, buddy string) (*pb.SafetyNumber, error) {
	return g.c.GetSafetyNumber(ctx, &pb.GetSafetyNumberRequest{Buddy: buddy})
}

func (g *grpcClient) SendIM(ctx context.Context, buddy, text string) (*pb.SendIMResponse, error) {
	return g.c.SendIM(ctx, &pb.SendIMRequest{Buddy: buddy, Text: text})
}

func (g *grpcClient) History(ctx context.Context, buddy string, limit uint32) ([]*pb.Message, error) {
	r, err := g.c.History(ctx, &pb.HistoryRequest{Buddy: buddy, Limit: limit})
	return r.GetMessages(), err
}

func (g *grpcClient) SetPresence(ctx context.Context, state pb.PresenceState, away string) (*pb.Presence, error) {
	return g.c.SetPresence(ctx, &pb.SetPresenceRequest{State: state, AwayMessage: away})
}

func (g *grpcClient) Subscribe(ctx context.Context) (EventStream, error) {
	return g.c.SubscribeEvents(ctx, &pb.SubscribeEventsRequest{})
}

func (g *grpcClient) Close() error { return g.conn.Close() }

// errText is an error as one line for the screen: the gRPC message without
// its "daemon: " prefix. The caller cleans it before showing it.
func errText(err error) string {
	if err == nil {
		return ""
	}
	if nr := (*NotRunningError)(nil); errors.As(err, &nr) {
		return nr.Error()
	}
	if st, ok := status.FromError(err); ok {
		msg := st.Message()
		for _, p := range []string{"daemon: ", "store: "} {
			if len(msg) > len(p) && msg[:len(p)] == p {
				msg = msg[len(p):]
			}
		}
		switch st.Code() {
		case codes.Unavailable:
			return "openaimd is not answering"
		case codes.DeadlineExceeded:
			return "openaimd did not answer in time"
		}
		return msg
	}
	return err.Error()
}

// callTimeout bounds one unary call.
const callTimeout = 10 * time.Second

func withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, callTimeout)
}
