package mesh

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/aghman/openaim/internal/meshpb"
)

// BroadcastAddr is Meshtastic's broadcast node number.
const BroadcastAddr uint32 = 0xFFFFFFFF

// HeartbeatInterval keeps serial links from being considered idle by the
// firmware (the Python client uses the same interval).
const HeartbeatInterval = 5 * time.Minute

// Event is delivered on Client.Events.
type Event interface{ isEvent() }

// PacketEvent is a mesh packet received by the radio and passed to us.
type PacketEvent struct {
	At     time.Time
	Packet *pb.MeshPacket
}

// QueueStatusEvent reports the radio's TX queue after it accepts or rejects a packet.
type QueueStatusEvent struct {
	At     time.Time
	Status *pb.QueueStatus
}

// LogEvent is a line of firmware log output (from debug text on serial, or a
// LogRecord frame).
type LogEvent struct {
	At   time.Time
	Line string
}

// RebootedEvent means the radio rebooted; its config snapshot may be stale.
type RebootedEvent struct{ At time.Time }

// NodeEvent is a NodeDB update pushed by the radio after the initial handshake.
type NodeEvent struct {
	At   time.Time
	Node *pb.NodeInfo
}

func (PacketEvent) isEvent()      {}
func (QueueStatusEvent) isEvent() {}
func (LogEvent) isEvent()         {}
func (RebootedEvent) isEvent()    {}
func (NodeEvent) isEvent()        {}

// Snapshot is the radio state collected during the want_config handshake and
// kept up to date afterwards.
type Snapshot struct {
	MyInfo        *pb.MyNodeInfo
	Metadata      *pb.DeviceMetadata
	Nodes         map[uint32]*pb.NodeInfo
	Channels      map[int32]*pb.Channel
	Config        []*pb.Config
	ModuleConfig  []*pb.ModuleConfig
	ConfigDoneAt  time.Time
	HandshakeTook time.Duration
}

// MyNodeNum returns the local node number, or 0 if unknown.
func (s *Snapshot) MyNodeNum() uint32 { return s.MyInfo.GetMyNodeNum() }

// Self returns the local node's NodeInfo, if the radio sent it.
func (s *Snapshot) Self() *pb.NodeInfo { return s.Nodes[s.MyNodeNum()] }

// LoRa returns the LoRa config section, or nil.
func (s *Snapshot) LoRa() *pb.Config_LoRaConfig {
	for _, c := range s.Config {
		if l := c.GetLora(); l != nil {
			return l
		}
	}
	return nil
}

// Device returns the device config section, or nil.
func (s *Snapshot) Device() *pb.Config_DeviceConfig {
	for _, c := range s.Config {
		if d := c.GetDevice(); d != nil {
			return d
		}
	}
	return nil
}

// MQTT returns the MQTT module config, or nil.
func (s *Snapshot) MQTT() *pb.ModuleConfig_MQTTConfig {
	for _, c := range s.ModuleConfig {
		if m := c.GetMqtt(); m != nil {
			return m
		}
	}
	return nil
}

// SendRequest describes an outgoing Data packet.
type SendRequest struct {
	To       uint32 // node number or BroadcastAddr
	Channel  uint32 // channel index
	PortNum  pb.PortNum
	Payload  []byte
	WantAck  bool
	HopLimit uint32 // 0 = firmware default
}

// AckKind classifies the first routing response to a sent packet.
type AckKind int

const (
	// AckNone: no routing response arrived (yet).
	AckNone AckKind = iota
	// AckDestination: the destination node acknowledged (DMs with want_ack).
	AckDestination
	// AckImplicit: our own radio reported success, e.g. it heard a neighbour
	// rebroadcast a broadcast packet.
	AckImplicit
	// AckNak: a routing error (local or remote); see Result.Reason.
	AckNak
)

func (k AckKind) String() string {
	switch k {
	case AckDestination:
		return "dest-ack"
	case AckImplicit:
		return "implicit-ack"
	case AckNak:
		return "nak"
	default:
		return "none"
	}
}

// Result is what came back for one sent packet.
type Result struct {
	ID       uint32
	SentAt   time.Time
	QueuedAt time.Time // zero if no QueueStatus arrived
	QueueRes int32     // QueueStatus.res; 0 = accepted
	AckAt    time.Time // zero if no routing response arrived
	Ack      AckKind
	AckFrom  uint32
	Reason   pb.Routing_Error
}

// Pending tracks a packet after Send.
type Pending struct {
	ID     uint32
	queued chan struct{}
	done   chan struct{}

	mu  sync.Mutex
	res Result
}

// Queued is closed when the radio's QueueStatus for this packet arrives.
func (p *Pending) Queued() <-chan struct{} { return p.queued }

// Done is closed when the first routing response (ack or NAK) arrives.
func (p *Pending) Done() <-chan struct{} { return p.done }

// Result returns a copy of what has been observed so far.
func (p *Pending) Result() Result {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.res
}

// Wait blocks until a routing response arrives or ctx ends, then returns the
// result observed so far.
func (p *Pending) Wait(ctx context.Context) Result {
	select {
	case <-p.done:
	case <-ctx.Done():
	}
	return p.Result()
}

// Client is a Meshtastic client-API session over a serial or TCP stream.
type Client struct {
	rw     io.ReadWriteCloser
	fr     *FrameReader
	fw     *FrameWriter
	events chan Event
	// DroppedEvents counts events discarded because the consumer fell behind.
	DroppedEvents atomic.Uint64

	mu         sync.Mutex
	snap       Snapshot
	pending    map[uint32]*Pending
	nonce      uint32
	configDone chan struct{}

	closeOnce sync.Once
	closed    chan struct{}
	readErr   error
}

// NewClient wraps an open connection. Call Start before anything else.
func NewClient(rw io.ReadWriteCloser) *Client {
	c := &Client{
		rw:         rw,
		fr:         NewFrameReader(rw),
		fw:         NewFrameWriter(rw),
		events:     make(chan Event, 256),
		pending:    make(map[uint32]*Pending),
		configDone: make(chan struct{}),
		closed:     make(chan struct{}),
		snap: Snapshot{
			Nodes:    make(map[uint32]*pb.NodeInfo),
			Channels: make(map[int32]*pb.Channel),
		},
	}
	c.fr.OnDebugLine = func(l string) { c.emit(LogEvent{At: time.Now(), Line: l}) }
	return c
}

// Start runs the read loop and the want_config handshake. It returns once the
// radio has sent its full config, or with an error if ctx ends first.
func (c *Client) Start(ctx context.Context) error {
	c.nonce = randUint32()
	go c.readLoop()
	go c.heartbeatLoop()

	begin := time.Now()
	if err := c.write(&pb.ToRadio{PayloadVariant: &pb.ToRadio_WantConfigId{WantConfigId: c.nonce}}); err != nil {
		return fmt.Errorf("send want_config: %w", err)
	}
	select {
	case <-c.configDone:
		c.mu.Lock()
		c.snap.HandshakeTook = time.Since(begin)
		c.mu.Unlock()
		return nil
	case <-c.closed:
		return fmt.Errorf("radio connection closed during handshake: %w", c.readErr)
	case <-ctx.Done():
		return fmt.Errorf("waiting for radio config: %w", ctx.Err())
	}
}

// Events delivers received packets, queue status, logs and reboots. The
// channel is closed when the connection closes.
func (c *Client) Events() <-chan Event { return c.events }

// Snapshot returns a shallow copy of the current radio state.
func (c *Client) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.snap
	s.Nodes = make(map[uint32]*pb.NodeInfo, len(c.snap.Nodes))
	for k, v := range c.snap.Nodes {
		s.Nodes[k] = v
	}
	s.Channels = make(map[int32]*pb.Channel, len(c.snap.Channels))
	for k, v := range c.snap.Channels {
		s.Channels[k] = v
	}
	s.Config = append([]*pb.Config(nil), c.snap.Config...)
	s.ModuleConfig = append([]*pb.ModuleConfig(nil), c.snap.ModuleConfig...)
	return s
}

// Send hands a Data packet to the radio and returns a tracker for its queue
// status and routing response.
func (c *Client) Send(req SendRequest) (*Pending, error) {
	id := randUint32()
	p := &Pending{ID: id, queued: make(chan struct{}), done: make(chan struct{})}
	p.res.ID = id

	pkt := &pb.MeshPacket{
		To:       req.To,
		Channel:  req.Channel,
		Id:       id,
		WantAck:  req.WantAck,
		HopLimit: req.HopLimit,
		PayloadVariant: &pb.MeshPacket_Decoded{Decoded: &pb.Data{
			Portnum: req.PortNum,
			Payload: req.Payload,
		}},
	}

	c.mu.Lock()
	c.pending[id] = p
	c.mu.Unlock()

	p.mu.Lock()
	p.res.SentAt = time.Now()
	p.mu.Unlock()
	if err := c.write(&pb.ToRadio{PayloadVariant: &pb.ToRadio_Packet{Packet: pkt}}); err != nil {
		c.forget(id)
		return nil, err
	}
	return p, nil
}

// Forget stops tracking a packet (call after you are done waiting on it).
func (c *Client) Forget(p *Pending) { c.forget(p.ID) }

func (c *Client) forget(id uint32) {
	c.mu.Lock()
	delete(c.pending, id)
	c.mu.Unlock()
}

// Close politely disconnects and closes the connection.
func (c *Client) Close() error {
	_ = c.write(&pb.ToRadio{PayloadVariant: &pb.ToRadio_Disconnect{Disconnect: true}})
	err := c.rw.Close()
	<-c.closed
	return err
}

func (c *Client) write(m *pb.ToRadio) error {
	b, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	return c.fw.WriteFrame(b)
}

func (c *Client) heartbeatLoop() {
	t := time.NewTicker(HeartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-t.C:
			_ = c.write(&pb.ToRadio{PayloadVariant: &pb.ToRadio_Heartbeat{Heartbeat: &pb.Heartbeat{Nonce: randUint32()}}})
		}
	}
}

func (c *Client) readLoop() {
	defer func() {
		c.closeOnce.Do(func() { close(c.closed) })
		close(c.events)
	}()
	for {
		b, err := c.fr.ReadFrame()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				c.readErr = err
			}
			return
		}
		var m pb.FromRadio
		if err := proto.Unmarshal(b, &m); err != nil {
			c.emit(LogEvent{At: time.Now(), Line: fmt.Sprintf("openaim: undecodable FromRadio (%d bytes): %v", len(b), err)})
			continue
		}
		c.handle(&m)
	}
}

func (c *Client) handle(m *pb.FromRadio) {
	now := time.Now()
	switch v := m.PayloadVariant.(type) {
	case *pb.FromRadio_MyInfo:
		c.mu.Lock()
		c.snap.MyInfo = v.MyInfo
		c.mu.Unlock()
	case *pb.FromRadio_Metadata:
		c.mu.Lock()
		c.snap.Metadata = v.Metadata
		c.mu.Unlock()
	case *pb.FromRadio_NodeInfo:
		c.mu.Lock()
		c.snap.Nodes[v.NodeInfo.GetNum()] = v.NodeInfo
		done := !c.snap.ConfigDoneAt.IsZero()
		c.mu.Unlock()
		if done {
			c.emit(NodeEvent{At: now, Node: v.NodeInfo})
		}
	case *pb.FromRadio_Channel:
		c.mu.Lock()
		c.snap.Channels[v.Channel.GetIndex()] = v.Channel
		c.mu.Unlock()
	case *pb.FromRadio_Config:
		c.mu.Lock()
		c.snap.Config = append(c.snap.Config, v.Config)
		c.mu.Unlock()
	case *pb.FromRadio_ModuleConfig:
		c.mu.Lock()
		c.snap.ModuleConfig = append(c.snap.ModuleConfig, v.ModuleConfig)
		c.mu.Unlock()
	case *pb.FromRadio_ConfigCompleteId:
		if v.ConfigCompleteId != c.nonce {
			return // a reply to some earlier client's request
		}
		c.mu.Lock()
		first := c.snap.ConfigDoneAt.IsZero()
		c.snap.ConfigDoneAt = now
		c.mu.Unlock()
		if first {
			close(c.configDone)
		}
	case *pb.FromRadio_QueueStatus:
		c.onQueueStatus(now, v.QueueStatus)
		c.emit(QueueStatusEvent{At: now, Status: v.QueueStatus})
	case *pb.FromRadio_Packet:
		c.onPacket(now, v.Packet)
		c.emit(PacketEvent{At: now, Packet: v.Packet})
	case *pb.FromRadio_LogRecord:
		c.emit(LogEvent{At: now, Line: v.LogRecord.GetMessage()})
	case *pb.FromRadio_Rebooted:
		c.emit(RebootedEvent{At: now})
	}
}

func (c *Client) onQueueStatus(now time.Time, qs *pb.QueueStatus) {
	c.mu.Lock()
	p := c.pending[qs.GetMeshPacketId()]
	c.mu.Unlock()
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.res.QueuedAt.IsZero() {
		return
	}
	p.res.QueuedAt = now
	p.res.QueueRes = qs.GetRes()
	close(p.queued)
}

// onPacket matches ROUTING_APP responses to packets we sent.
func (c *Client) onPacket(now time.Time, pkt *pb.MeshPacket) {
	d := pkt.GetDecoded()
	if d == nil || d.GetPortnum() != pb.PortNum_ROUTING_APP || d.GetRequestId() == 0 {
		return
	}
	c.mu.Lock()
	p := c.pending[d.GetRequestId()]
	me := c.snap.MyInfo.GetMyNodeNum()
	c.mu.Unlock()
	if p == nil {
		return
	}
	var r pb.Routing
	if err := proto.Unmarshal(d.GetPayload(), &r); err != nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.res.AckAt.IsZero() {
		return // only the first response counts
	}
	p.res.AckAt = now
	p.res.AckFrom = pkt.GetFrom()
	p.res.Reason = r.GetErrorReason()
	switch {
	case p.res.Reason != pb.Routing_NONE:
		p.res.Ack = AckNak
	case pkt.GetFrom() == me:
		p.res.Ack = AckImplicit
	default:
		p.res.Ack = AckDestination
	}
	close(p.done)
}

func (c *Client) emit(e Event) {
	select {
	case c.events <- e:
	default:
		c.DroppedEvents.Add(1)
	}
}

func randUint32() uint32 {
	var b [4]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			panic(err)
		}
		// 0 means "unset" in Meshtastic packet IDs and config nonces.
		if v := binary.BigEndian.Uint32(b[:]); v != 0 {
			return v
		}
	}
}
