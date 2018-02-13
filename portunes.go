// Package portunes password hashing daemon accessible via gRPC.
package portunes

//go:generate protoc ./portunes.proto --go_out=plugins=grpc:internal/proto
