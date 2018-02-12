package main

import (
	"log"
	"net/http"

	"github.com/tmthrgd/portunes"
)

func main() {
	mux := http.NewServeMux()
	mux.Handle(portunes.HashPath, http.HandlerFunc(portunes.Hash))
	mux.Handle(portunes.VerifyPath, http.HandlerFunc(portunes.Verify))

	log.Println("Listening on 0.0.0.0:8080")
	log.Fatal(http.ListenAndServe("0.0.0.0:8080", mux))
}
