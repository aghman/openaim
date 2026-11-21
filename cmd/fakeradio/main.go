// Command fakeradio serves an in-memory fake Meshtastic radio over TCP so
// meshspike (and later openaimd) can be exercised without hardware:
//
//	go run ./cmd/fakeradio &
//	go run ./cmd/meshspike info --tcp 127.0.0.1:14403
//
// It accepts one client at a time. Broadcasts over 233 B and DMs over 221 B
// get a TOO_LARGE NAK; DMs to !11111111 are acked by that "peer".
package main

import (
	"flag"
	"log"
	"net"

	"github.com/aghman/openaim/internal/transport/mesh/meshtest"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:14403", "address to listen on")
	flag.Parse()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("fake radio listening on %s", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("client connected from %s", conn.RemoteAddr())
		meshtest.New().Serve(conn)
		conn.Close()
		log.Printf("client disconnected")
	}
}
