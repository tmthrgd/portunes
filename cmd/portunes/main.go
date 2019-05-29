package main

import (
	"flag"
	"log"
	"net"
	"os"
	"runtime"

	"go.tmthrgd.dev/portunes"
	"google.golang.org/grpc"
)

func main() {
	addr := flag.String("addr", ":8080", "the address to listen on")
	time := flag.Uint("time", 1, "the number of argon2 iterations")
	memory := flag.Uint("memory", 64*1024, "the argon2 memory size")
	threads := flag.Uint("threads", uint(1+runtime.GOMAXPROCS(0))/2, "the degree of parallelism for argon2")
	flag.Parse()

	if uint(uint32(*time)) != *time ||
		uint(uint32(*memory)) != *memory ||
		uint(uint8(*threads)) != *threads {
		flag.Usage()
		os.Exit(1)
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	gs := grpc.NewServer()
	portunes.NewServer(uint32(*time), uint32(*memory), uint8(*threads)).Attach(gs)
	log.Fatal(gs.Serve(ln))
}
