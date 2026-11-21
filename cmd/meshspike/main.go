// Command meshspike is the M0 Meshtastic spike: it connects to a radio over
// USB serial or TCP and measures what docs/design.md §6.2 and §14 (M0) need to
// know — usable payload per route, ack behaviour and timing, and which radio
// settings would block OpenAIM traffic.
//
//	meshspike ports
//	meshspike info       [--port DEV | --tcp HOST]
//	meshspike listen     [--port DEV | --tcp HOST] [--echo] [--all] [--logs] [--jsonl FILE]
//	meshspike send       [--port DEV | --tcp HOST] --to NODE [--size N] [--count N] [--interval D] [--want-ack] [--jsonl FILE]
//	meshspike probe-size [--port DEV | --tcp HOST] --to NODE [--min N] [--max N] [--interval D] [--jsonl FILE]
//
// NODE is "broadcast", "!a1b2c3d4" (hex node ID) or a decimal node number.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	pb "github.com/aghman/openaim/internal/meshpb"
	"github.com/aghman/openaim/internal/transport/mesh"
)

const usage = `meshspike — OpenAIM M0 Meshtastic spike

Commands:
  ports        list serial ports that look like radios
  info         connect, run the config handshake, print what matters for OpenAIM
  listen       print received packets; --echo answers test DMs so 'send' can time round trips
  send         send numbered test payloads and report queue status, acks and timing
  probe-size   binary-search the largest payload the radio accepts on a route

Run 'meshspike <command> -h' for flags. Transmitting commands use airtime on a
shared mesh: keep counts low and intervals long.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "ports":
		err = runPorts()
	case "info":
		err = runInfo(ctx, args)
	case "listen":
		err = runListen(ctx, args)
	case "send":
		err = runSend(ctx, args)
	case "probe-size":
		err = runProbe(ctx, args)
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "meshspike:", err)
		os.Exit(1)
	}
}

// connFlags are shared by every command that talks to a radio.
type connFlags struct {
	port    string
	tcp     string
	timeout time.Duration
}

func (c *connFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.port, "port", "", "serial device (default: auto-detect a single USB radio)")
	fs.StringVar(&c.tcp, "tcp", "", "radio host[:port] for the TCP API (port defaults to 4403)")
	fs.DurationVar(&c.timeout, "handshake-timeout", 60*time.Second, "max time to wait for the radio's config")
}

func (c *connFlags) connect(ctx context.Context) (*mesh.Client, error) {
	if c.port != "" && c.tcp != "" {
		return nil, errors.New("use either --port or --tcp, not both")
	}
	cctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var (
		client *mesh.Client
		desc   string
	)
	switch {
	case c.tcp != "":
		conn, err := mesh.DialTCP(cctx, c.tcp)
		if err != nil {
			return nil, err
		}
		client, desc = mesh.NewClient(conn), "tcp "+c.tcp
	default:
		port := c.port
		if port == "" {
			var err error
			if port, err = autodetectPort(); err != nil {
				return nil, err
			}
		}
		conn, err := mesh.OpenSerial(port)
		if err != nil {
			return nil, err
		}
		client, desc = mesh.NewClient(conn), "serial "+port
	}
	fmt.Fprintf(os.Stderr, "connecting via %s …\n", desc)
	if err := client.Start(cctx); err != nil {
		client.Close()
		return nil, err
	}
	return client, nil
}

// radioLike matches device names that USB serial radios (CP210x, CH34x,
// FTDI, native USB CDC) show up as.
func radioLike(p string) bool {
	base := filepath.Base(p)
	for _, prefix := range []string{"cu.usbserial", "cu.usbmodem", "cu.SLAB_USBtoUART", "cu.wchusbserial", "ttyUSB", "ttyACM", "COM"} {
		if strings.HasPrefix(base, prefix) {
			return true
		}
	}
	return false
}

func candidatePorts() ([]string, error) {
	all, err := mesh.ListSerialPorts()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, p := range all {
		if radioLike(p) {
			out = append(out, p)
		}
	}
	return out, nil
}

func autodetectPort() (string, error) {
	ports, err := candidatePorts()
	if err != nil {
		return "", fmt.Errorf("list serial ports: %w", err)
	}
	switch len(ports) {
	case 0:
		return "", errors.New("no USB radio found; plug one in, or pass --port or --tcp")
	case 1:
		return ports[0], nil
	default:
		return "", fmt.Errorf("several candidate ports (%s); pick one with --port", strings.Join(ports, ", "))
	}
}

func runPorts() error {
	ports, err := candidatePorts()
	if err != nil {
		return err
	}
	if len(ports) == 0 {
		fmt.Println("no USB serial radios found")
		return nil
	}
	for _, p := range ports {
		fmt.Println(p)
	}
	return nil
}

// parseNode accepts "broadcast", "!hex" or decimal.
func parseNode(s string) (uint32, error) {
	switch strings.ToLower(s) {
	case "", "broadcast", "all", "^all":
		return mesh.BroadcastAddr, nil
	}
	if strings.HasPrefix(s, "!") {
		v, err := strconv.ParseUint(s[1:], 16, 32)
		if err != nil {
			return 0, fmt.Errorf("bad node ID %q: %w", s, err)
		}
		return uint32(v), nil
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("bad node %q (want broadcast, !hex or decimal): %w", s, err)
	}
	return uint32(v), nil
}

func nodeID(n uint32) string {
	if n == mesh.BroadcastAddr {
		return "broadcast"
	}
	return fmt.Sprintf("!%08x", n)
}

func portNumFlag(fs *flag.FlagSet) *int {
	return fs.Int("portnum", int(pb.PortNum_PRIVATE_APP), "Meshtastic PortNum for test traffic (private range 256–511)")
}

func checkPortNum(p int) error {
	if p < int(pb.PortNum_PRIVATE_APP) || p > int(pb.PortNum_MAX) {
		return fmt.Errorf("--portnum %d is outside the private range 256–511", p)
	}
	return nil
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
