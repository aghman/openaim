package mesh

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"go.bug.st/serial"
)

// DefaultTCPPort is the Meshtastic firmware's TCP client API port.
const DefaultTCPPort = "4403"

// OpenSerial opens a radio's USB serial port (115200 8N1, the firmware default)
// and sends the wake sequence.
func OpenSerial(path string) (io.ReadWriteCloser, error) {
	p, err := serial.Open(path, &serial.Mode{BaudRate: 115200, DataBits: 8, Parity: serial.NoParity, StopBits: serial.OneStopBit})
	if err != nil {
		return nil, fmt.Errorf("open serial %s: %w", path, err)
	}
	if _, err := p.Write(WakeSequence); err != nil {
		p.Close()
		return nil, fmt.Errorf("wake %s: %w", path, err)
	}
	// Give the firmware's parser a moment to resync, as the Python client does.
	time.Sleep(100 * time.Millisecond)
	return p, nil
}

// DialTCP connects to a WiFi/Ethernet radio's client API. addr may omit the port.
func DialTCP(ctx context.Context, addr string) (io.ReadWriteCloser, error) {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(strings.Trim(addr, "[]"), DefaultTCPPort)
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	return c, nil
}

// ListSerialPorts returns candidate serial device paths.
func ListSerialPorts() ([]string, error) { return serial.GetPortsList() }
