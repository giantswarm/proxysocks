package main

import (
	"context"
	"log"
	"net"
	"os"

	"github.com/things-go/go-socks5"
)

func main() {
	logger := log.New(os.Stdout, "socks5: ", log.LstdFlags)

	// Create a SOCKS5 server
	server := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(logger)),
		socks5.WithDial(LoggingDialer),
	)

	// Create SOCKS5 proxy on localhost port 8000
	if err := server.ListenAndServe("tcp", ":8000"); err != nil {
		panic(err)
	}

}

func LoggingDialer(ctx context.Context, network, address string) (net.Conn, error) {
	log.Printf("New connection: %s %s", network, address)
	dialer := net.Dialer{}
	return dialer.DialContext(ctx, network, address)
}
