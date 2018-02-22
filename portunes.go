// Package portunes provides a password hashing client and server
// accessible via gRPC.
package portunes

//go:generate protoc ./portunes.proto --go_out=plugins=grpc:internal/proto
