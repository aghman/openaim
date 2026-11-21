package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	pb "github.com/aghman/openaim/internal/meshpb"
	"github.com/aghman/openaim/internal/transport/mesh"
)

func runInfo(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	var cf connFlags
	cf.register(fs)
	nodes := fs.Bool("nodes", false, "also list the radio's NodeDB")
	fs.Parse(args)

	c, err := cf.connect(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	s := c.Snapshot()
	printInfo(os.Stdout, &s, *nodes)
	return nil
}

// printInfo reports the radio facts relevant to OpenAIM's mesh design and
// flags settings that would block or expose OpenAIM traffic. It never prints
// channel keys.
func printInfo(w io.Writer, s *mesh.Snapshot, listNodes bool) {
	var warnings []string
	warn := func(f string, a ...any) { warnings = append(warnings, fmt.Sprintf(f, a...)) }

	self := s.Self()
	fmt.Fprintf(w, "Node           %s  %q (%s)\n", nodeID(s.MyNodeNum()), self.GetUser().GetLongName(), self.GetUser().GetShortName())
	fmt.Fprintf(w, "Hardware       %v\n", s.Metadata.GetHwModel())
	fmt.Fprintf(w, "Firmware       %s  (PKC: %v)\n", s.Metadata.GetFirmwareVersion(), s.Metadata.GetHasPKC())
	fmt.Fprintf(w, "Handshake      %v, %d nodes in NodeDB\n", s.HandshakeTook.Round(1e6), len(s.Nodes))

	if self.GetUser().GetIsLicensed() {
		warn("radio is in licensed (ham) mode: OpenAIM will refuse to transmit on it (design §10.5)")
	}

	if l := s.LoRa(); l != nil {
		preset := l.GetModemPreset().String()
		if !l.GetUsePreset() {
			preset = fmt.Sprintf("custom (BW %d kHz, SF %d, CR 4/%d)", l.GetBandwidth(), l.GetSpreadFactor(), l.GetCodingRate())
		}
		fmt.Fprintf(w, "LoRa           region %v, %s, hop limit %d, TX enabled %v\n", l.GetRegion(), preset, l.GetHopLimit(), l.GetTxEnabled())
		if !l.GetTxEnabled() {
			warn("LoRa TX is disabled: sends will queue but never go on air")
		}
		if l.GetRegion() == pb.Config_LoRaConfig_UNSET {
			warn("LoRa region is UNSET: the radio will not transmit until a region is configured")
		}
	}

	if d := s.Device(); d != nil {
		fmt.Fprintf(w, "Device role    %v, rebroadcast mode %v\n", d.GetRole(), d.GetRebroadcastMode())
		switch d.GetRebroadcastMode() {
		case pb.Config_DeviceConfig_CORE_PORTNUMS_ONLY:
			warn("rebroadcast mode CORE_PORTNUMS_ONLY: this node will not relay private-PortNum (OpenAIM) packets for others")
		case pb.Config_DeviceConfig_NONE:
			warn("rebroadcast mode NONE: this node relays nothing")
		}
	}

	if self != nil {
		if dm := self.GetDeviceMetrics(); dm != nil {
			fmt.Fprintf(w, "Airtime        channel utilization %.1f%%, own TX %.2f%% (last hour)\n", dm.GetChannelUtilization(), dm.GetAirUtilTx())
		}
	}

	mqtt := s.MQTT()
	fmt.Fprintf(w, "MQTT module    enabled %v, proxy-to-client %v\n", mqtt.GetEnabled(), mqtt.GetProxyToClientEnabled())

	fmt.Fprintf(w, "\nChannels\n")
	idx := make([]int, 0, len(s.Channels))
	for i := range s.Channels {
		idx = append(idx, int(i))
	}
	sort.Ints(idx)
	for _, i := range idx {
		ch := s.Channels[int32(i)]
		if ch.GetRole() == pb.Channel_DISABLED {
			continue
		}
		st := ch.GetSettings()
		name := st.GetName()
		if name == "" {
			name = "(preset default)"
		}
		fmt.Fprintf(w, "  [%d] %-9v %-18q key: %-28s uplink %-5v downlink %-5v channel-AEAD %v\n",
			i, ch.GetRole(), name, describePSK(st.GetPsk()), st.GetUplinkEnabled(), st.GetDownlinkEnabled(), st.GetUseAead())
		if st.GetUplinkEnabled() && mqtt.GetEnabled() {
			warn("channel %d uplinks to MQTT: frames on it are published off-mesh and become globally replayable (design §6.2, §8.9)", i)
		}
	}

	fmt.Fprintf(w, "\nPayload        DATA_PAYLOAD_LEN = %d bytes (protocol constant; use 'probe-size' to measure per route)\n", pb.Constants_DATA_PAYLOAD_LEN)

	if listNodes {
		fmt.Fprintf(w, "\nNodeDB\n")
		nums := make([]uint32, 0, len(s.Nodes))
		for n := range s.Nodes {
			nums = append(nums, n)
		}
		sort.Slice(nums, func(a, b int) bool { return nums[a] < nums[b] })
		for _, n := range nums {
			ni := s.Nodes[n]
			fmt.Fprintf(w, "  %s  %-5s %-24q hops %-2d snr %5.1f  pubkey %-5v mqtt %v\n",
				nodeID(n), ni.GetUser().GetShortName(), ni.GetUser().GetLongName(), ni.GetHopsAway(), ni.GetSnr(),
				len(ni.GetUser().GetPublicKey()) == 32, ni.GetViaMqtt())
		}
	}

	if len(warnings) > 0 {
		fmt.Fprintf(w, "\nWarnings\n")
		for _, x := range warnings {
			fmt.Fprintf(w, "  ! %s\n", x)
		}
	}
}

// describePSK classifies a channel key without revealing it.
func describePSK(psk []byte) string {
	switch {
	case len(psk) == 0:
		return "none (plaintext)"
	case len(psk) == 1 && psk[0] == 0:
		return "none (plaintext)"
	case len(psk) == 1 && psk[0] == 1:
		return "default (publicly known)"
	case len(psk) == 1:
		return fmt.Sprintf("default+%d (publicly known)", psk[0]-1)
	case len(psk) == 16:
		return "custom AES-128"
	case len(psk) == 32:
		return "custom AES-256"
	default:
		return strings.TrimSpace(fmt.Sprintf("unusual length %d", len(psk)))
	}
}
