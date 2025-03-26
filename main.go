package main

import (
	"log"
	"os"

	"github.com/things-go/go-socks5"
)

func main() {
	logger := log.New(os.Stdout, "socks5: ", log.LstdFlags)

	// Create a SOCKS5 server
	server := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(logger)),
	)

	// Create SOCKS5 proxy on localhost port 8000
	if err := server.ListenAndServe("tcp", ":8000"); err != nil {
		panic(err)
	}

}
