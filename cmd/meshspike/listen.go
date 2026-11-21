package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	pb "github.com/aghman/openaim/internal/meshpb"
	"github.com/aghman/openaim/internal/transport/mesh"
)

// echoMinGap rate-limits echo replies so a misbehaving sender can't make this
// radio flood the mesh.
const echoMinGap = 5 * time.Second

type rxRecord struct {
	Kind     string       `json:"kind"` // "rx"
	At       time.Time    `json:"at"`
	From     string       `json:"from"`
	To       string       `json:"to"`
	Channel  uint32       `json:"channel"`
	PortNum  string       `json:"portnum"`
	Size     int          `json:"size"`
	Hops     int          `json:"hops"` // -1 if the sender's firmware didn't set hop_start
	SNR      float32      `json:"snr"`
	RSSI     int32        `json:"rssi"`
	PKI      bool         `json:"pki"`
	ViaMQTT  bool         `json:"via_mqtt"`
	Relay    uint32       `json:"relay_node"`
	Seq      *uint32      `json:"seq,omitempty"`
	Echo     bool         `json:"echo,omitempty"`
	OneWayMS *float64     `json:"one_way_ms,omitempty"` // only meaningful if both hosts' clocks are synced
	Radio    radioContext `json:"radio"`
}

func runListen(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("listen", flag.ExitOnError)
	var cf connFlags
	cf.register(fs)
	portnum := portNumFlag(fs)
	all := fs.Bool("all", false, "show packets on every PortNum, not just --portnum")
	echo := fs.Bool("echo", false, "reply to meshspike test DMs addressed to this node (never to broadcasts)")
	logs := fs.Bool("logs", false, "print firmware log lines")
	jsonl := fs.String("jsonl", "", "append received-packet records to this JSONL file")
	fs.Parse(args)
	if err := checkPortNum(*portnum); err != nil {
		return err
	}

	rec, err := openRecorder(*jsonl)
	if err != nil {
		return err
	}
	defer rec.Close()

	c, err := cf.connect(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	s := c.Snapshot()
	rc := contextOf(&s)
	me := s.MyNodeNum()
	fmt.Fprintf(os.Stderr, "listening as %s on PortNum %d (Ctrl-C to stop)\n", nodeID(me), *portnum)

	var lastEcho time.Time
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e, ok := <-c.Events():
			if !ok {
				return fmt.Errorf("radio connection closed")
			}
			switch e := e.(type) {
			case mesh.LogEvent:
				if *logs {
					fmt.Fprintf(os.Stderr, "log  %s\n", e.Line)
				}
			case mesh.RebootedEvent:
				fmt.Fprintln(os.Stderr, "radio rebooted")
			case mesh.PacketEvent:
				p := e.Packet
				d := p.GetDecoded()
				ours := d != nil && d.GetPortnum() == pb.PortNum(*portnum)
				if !ours && !*all {
					continue
				}
				r := describeRx(e, rc)
				line := fmt.Sprintf("rx   %s → %s ch%d %-16s %3dB hops %2d snr %5.1f rssi %4d pki %-5v",
					r.From, r.To, r.Channel, r.PortNum, r.Size, r.Hops, r.SNR, r.RSSI, r.PKI)
				if r.ViaMQTT {
					line += " via-MQTT"
				}
				if ours {
					if tp, err := decodePayload(d.GetPayload()); err == nil {
						seq := tp.Seq
						r.Seq, r.Echo = &seq, tp.Echo
						ow := ms(e.At.Sub(tp.SentAt))
						r.OneWayMS = &ow
						line += fmt.Sprintf(" seq %d one-way %.0fms", tp.Seq, ow)
						if tp.Echo {
							line += " (echo)"
						}
						// Echo only direct requests, never broadcasts or echoes.
						if *echo && !tp.Echo && p.GetTo() == me && time.Since(lastEcho) >= echoMinGap {
							lastEcho = time.Now()
							if _, err := c.Send(mesh.SendRequest{
								To: p.GetFrom(), Channel: p.GetChannel(), PortNum: pb.PortNum(*portnum), Payload: echoOf(d.GetPayload()),
							}); err != nil {
								line += " echo-failed: " + err.Error()
							} else {
								line += " → echoed"
							}
						}
					}
				}
				fmt.Println(line)
				rec.write(r)
			}
		}
	}
}

func describeRx(e mesh.PacketEvent, rc radioContext) rxRecord {
	p := e.Packet
	d := p.GetDecoded()
	r := rxRecord{
		Kind: "rx", At: e.At, From: nodeID(p.GetFrom()), To: nodeID(p.GetTo()), Channel: p.GetChannel(),
		SNR: p.GetRxSnr(), RSSI: p.GetRxRssi(), PKI: p.GetPkiEncrypted(), ViaMQTT: p.GetViaMqtt(),
		Relay: p.GetRelayNode(), Hops: -1, Radio: rc,
	}
	if p.GetHopStart() > 0 {
		r.Hops = int(p.GetHopStart()) - int(p.GetHopLimit())
	}
	if d != nil {
		r.PortNum, r.Size = d.GetPortnum().String(), len(d.GetPayload())
	} else {
		r.PortNum, r.Size = "(encrypted)", len(p.GetEncrypted())
	}
	return r
}

func contextOf(s *mesh.Snapshot) radioContext {
	return radioContext{
		Node:        nodeID(s.MyNodeNum()),
		Firmware:    s.Metadata.GetFirmwareVersion(),
		Region:      s.LoRa().GetRegion().String(),
		Preset:      s.LoRa().GetModemPreset().String(),
		Rebroadcast: s.Device().GetRebroadcastMode().String(),
	}
}
