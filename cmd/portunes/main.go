package main

import (
	"flag"
	"log"
	"net"

	"github.com/tmthrgd/portunes"
	"google.golang.org/grpc"
)

func main() {
	addr := flag.String("addr", ":8080", "the address to listen on")
	flag.Parse()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	gs := grpc.NewServer()
	portunes.NewServer(3, 1<<19, 2).Attach(gs)
	log.Fatal(gs.Serve(ln))
}
