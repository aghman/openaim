// Package meshtest provides an in-memory fake Meshtastic radio that speaks the
// client stream API, for testing code built on internal/transport/mesh.
//
// It models only what the client relies on: the want_config handshake,
// QueueStatus after each packet, routing acks/NAKs (including TOO_LARGE), and
// injection of received packets. It does not model the mesh itself.
package meshtest

import (
	"net"
	"sync"

	"google.golang.org/protobuf/proto"

	pb "github.com/aghman/openaim/internal/meshpb"
	"github.com/aghman/openaim/internal/transport/mesh"
)

// FakeRadio is the radio side of an in-memory client connection.
type FakeRadio struct {
	MyNode uint32
	// Peers are nodes in the fake NodeDB. Packets sent to them with want_ack
	// are acked by them (unless listed in Silent).
	Peers []uint32
	// Silent peers never ack (simulates an unreachable node).
	Silent map[uint32]bool
	// MaxBroadcastPayload / MaxDMPayload: payloads above these get a local
	// TOO_LARGE NAK, mimicking the firmware's encryption size check. DMs are
	// smaller because Meshtastic PKC adds overhead.
	MaxBroadcastPayload int
	MaxDMPayload        int
	// ImplicitAckBroadcasts makes want_ack broadcasts get an implicit ack from
	// our own node, as when a neighbour's rebroadcast is overheard.
	ImplicitAckBroadcasts bool
	// Lora and Channels populate the config handshake.
	Lora     *pb.Config_LoRaConfig
	Channels []*pb.Channel

	conn net.Conn
	fw   *mesh.FrameWriter

	mu   sync.Mutex
	sent []*pb.MeshPacket
}

// New returns a radio with defaults resembling a stock US LongFast node.
func New() *FakeRadio {
	return &FakeRadio{
		MyNode:                0x0A0B0C0D,
		Peers:                 []uint32{0x11111111},
		Silent:                map[uint32]bool{},
		MaxBroadcastPayload:   233,
		MaxDMPayload:          221,
		ImplicitAckBroadcasts: true,
		Lora: &pb.Config_LoRaConfig{
			UsePreset:   true,
			ModemPreset: pb.Config_LoRaConfig_LONG_FAST,
			Region:      pb.Config_LoRaConfig_US,
			HopLimit:    3,
			TxEnabled:   true,
		},
		Channels: []*pb.Channel{{
			Index:    0,
			Role:     pb.Channel_PRIMARY,
			Settings: &pb.ChannelSettings{Psk: []byte{1}},
		}},
	}
}

// Start returns the client end of an in-memory connection and begins serving.
func (r *FakeRadio) Start() net.Conn {
	client, radio := net.Pipe()
	go r.Serve(radio)
	return client
}

// Serve speaks the radio side of the client API on conn until it closes. A
// FakeRadio serves one connection at a time, like a real radio's serial port.
func (r *FakeRadio) Serve(conn net.Conn) {
	r.conn = conn
	r.fw = mesh.NewFrameWriter(conn)
	r.serve()
}

// Sent returns the packets the client has handed to the radio.
func (r *FakeRadio) Sent() []*pb.MeshPacket {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*pb.MeshPacket(nil), r.sent...)
}

// Deliver injects a packet as if the radio had received it from the mesh.
func (r *FakeRadio) Deliver(p *pb.MeshPacket) {
	r.send(&pb.FromRadio{PayloadVariant: &pb.FromRadio_Packet{Packet: p}})
}

// WriteDebug writes raw log text onto the stream, as firmware does on serial.
func (r *FakeRadio) WriteDebug(s string) { _, _ = r.conn.Write([]byte(s)) }

func (r *FakeRadio) send(m *pb.FromRadio) {
	b, err := proto.Marshal(m)
	if err != nil {
		panic(err)
	}
	_ = r.fw.WriteFrame(b)
}

func (r *FakeRadio) serve() {
	fr := mesh.NewFrameReader(r.conn)
	for {
		b, err := fr.ReadFrame()
		if err != nil {
			return
		}
		var m pb.ToRadio
		if proto.Unmarshal(b, &m) != nil {
			continue
		}
		switch v := m.PayloadVariant.(type) {
		case *pb.ToRadio_WantConfigId:
			r.sendConfig(v.WantConfigId)
		case *pb.ToRadio_Packet:
			r.onPacket(v.Packet)
		case *pb.ToRadio_Disconnect:
			r.conn.Close()
			return
		}
	}
}

func (r *FakeRadio) sendConfig(nonce uint32) {
	r.send(&pb.FromRadio{PayloadVariant: &pb.FromRadio_MyInfo{MyInfo: &pb.MyNodeInfo{MyNodeNum: r.MyNode}}})
	r.send(&pb.FromRadio{PayloadVariant: &pb.FromRadio_Metadata{Metadata: &pb.DeviceMetadata{FirmwareVersion: "2.8.3.fake", HasPKC: true}}})
	for _, n := range append([]uint32{r.MyNode}, r.Peers...) {
		r.send(&pb.FromRadio{PayloadVariant: &pb.FromRadio_NodeInfo{NodeInfo: &pb.NodeInfo{
			Num:  n,
			User: &pb.User{LongName: "fake", ShortName: "fk"},
		}}})
	}
	for _, ch := range r.Channels {
		r.send(&pb.FromRadio{PayloadVariant: &pb.FromRadio_Channel{Channel: ch}})
	}
	r.send(&pb.FromRadio{PayloadVariant: &pb.FromRadio_Config{Config: &pb.Config{PayloadVariant: &pb.Config_Lora{Lora: r.Lora}}}})
	r.send(&pb.FromRadio{PayloadVariant: &pb.FromRadio_Config{Config: &pb.Config{PayloadVariant: &pb.Config_Device{Device: &pb.Config_DeviceConfig{}}}}})
	r.send(&pb.FromRadio{PayloadVariant: &pb.FromRadio_ConfigCompleteId{ConfigCompleteId: nonce}})
}

func (r *FakeRadio) onPacket(p *pb.MeshPacket) {
	r.mu.Lock()
	r.sent = append(r.sent, p)
	r.mu.Unlock()

	limit := r.MaxBroadcastPayload
	if p.GetTo() != mesh.BroadcastAddr {
		limit = r.MaxDMPayload
	}
	if len(p.GetDecoded().GetPayload()) > limit {
		r.routing(r.MyNode, p.GetId(), pb.Routing_TOO_LARGE)
		return
	}
	r.send(&pb.FromRadio{PayloadVariant: &pb.FromRadio_QueueStatus{QueueStatus: &pb.QueueStatus{
		Res: 0, Free: 15, Maxlen: 16, MeshPacketId: p.GetId(),
	}}})
	if !p.GetWantAck() {
		return
	}
	switch {
	case p.GetTo() == mesh.BroadcastAddr:
		if r.ImplicitAckBroadcasts {
			r.routing(r.MyNode, p.GetId(), pb.Routing_NONE)
		}
	case r.isPeer(p.GetTo()) && !r.Silent[p.GetTo()]:
		r.routing(p.GetTo(), p.GetId(), pb.Routing_NONE)
	default:
		r.routing(r.MyNode, p.GetId(), pb.Routing_MAX_RETRANSMIT)
	}
}

func (r *FakeRadio) isPeer(n uint32) bool {
	for _, p := range r.Peers {
		if p == n {
			return true
		}
	}
	return false
}

func (r *FakeRadio) routing(from, requestID uint32, reason pb.Routing_Error) {
	payload, err := proto.Marshal(&pb.Routing{Variant: &pb.Routing_ErrorReason{ErrorReason: reason}})
	if err != nil {
		panic(err)
	}
	r.Deliver(&pb.MeshPacket{
		From: from,
		To:   r.MyNode,
		PayloadVariant: &pb.MeshPacket_Decoded{Decoded: &pb.Data{
			Portnum:   pb.PortNum_ROUTING_APP,
			Payload:   payload,
			RequestId: requestID,
		}},
	})
}
