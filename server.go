package portunes

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"sync/atomic"

	pb "github.com/tmthrgd/portunes/internal/proto"
	"golang.org/x/crypto/argon2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	saltLen = 16
	tagLen  = 16
)

type params struct {
	time, memory uint32
	threads      uint8
}

// Server represents a portunes.Hasher service.
type Server struct {
	params atomic.Value // *params

	rehash, dosProt func(ctx context.Context, time, memory uint32, threads uint8) bool
}

// NewServer creates a Server with the given paramaters.
//
// See SetParameters for recommended parameters.
func NewServer(time, memory uint32, threads uint8, opts ...ServerOption) *Server {
	s := new(Server)
	s.SetParameters(time, memory, threads)
	s.rehash = s.defaultRehash

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// SetParameters changes the Argon2id cost parameters the
// server is using to hash passwords.
//
// The CPU cost and parallism degree must be greater than
// zero. The time parameter specifies the number of passes
// over the memory and the memory parameter specifies the
// size of the memory in KiB. For example memory=64*1024
// sets the memory cost to ~64 MB. The number of threads
// can be adjusted to the numbers of available CPUs. The
// cost parameters should be increased as memory latency
// and CPU parallelism increases.
//
// The recommended parameters for non-interactive
// operations (taken from [1]) are time=1 and to use the
// maximum available memory. The x/crypto/argon2 package[2]
// recommends time=1 and memory=64*1024 as a sensible cost.
//
// This method is safe to call after Attach.
//
// [1] https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03#section-9.3
// [2] https://godoc.org/golang.org/x/crypto/argon2#IDKey
func (s *Server) SetParameters(time, memory uint32, threads uint8) {
	if time < 1 || threads < 1 {
		panic("portunes: invalid argon2 paramaters")
	}

	s.params.Store(&params{time, memory, threads})
}

func (s *Server) defaultRehash(ctx context.Context, time, memory uint32, threads uint8) bool {
	p := s.params.Load().(*params)
	return memory < p.memory
}

type pbServer struct{ *Server }

// Attach registers the portunes.Hasher service to the
// given grpc.Server.
func (s *Server) Attach(srv *grpc.Server) {
	pb.RegisterHasherServer(srv, pbServer{s})
}

func (s pbServer) Hash(ctx context.Context, req *pb.HashRequest) (*pb.HashResponse, error) {
	salt := make([]byte, saltLen, saltLen+len(req.Pepper))
	if _, err := rand.Read(salt); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	p := s.params.Load().(*params)

	hash := argon2.IDKey(
		[]byte(req.Password),
		append(salt, req.Pepper...),
		p.time, p.memory, p.threads, tagLen)

	res := make([]byte, 0, maxParamsLength+len(salt)+len(hash))
	res = appendParams(res, p.time, p.memory, p.threads)
	res = append(res, salt...)
	res = append(res, hash...)

	return &pb.HashResponse{
		Hash: res,
	}, nil
}

func (s pbServer) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	time, memory, threads, hash := consumeParams(req.Hash)
	if len(hash) != saltLen+tagLen {
		return nil, status.Error(codes.InvalidArgument, "invalid hash")
	}

	if s.dosProt != nil && !s.dosProt(ctx, time, memory, threads) {
		return nil, status.Error(codes.ResourceExhausted, "dos protection callback refused")
	}

	salt, hash := hash[:saltLen:saltLen], hash[saltLen:]

	expect := argon2.IDKey(
		[]byte(req.Password),
		append(salt, req.Pepper...),
		time, memory, threads, tagLen)

	valid := subtle.ConstantTimeCompare(expect, hash) == 1

	// Always call s.rehash regardless of password
	// validity to limit a potential side-channel leak.
	rehash := s.rehash != nil && s.rehash(ctx, time, memory, threads)

	return &pb.VerifyResponse{
		Valid: valid,

		// Never return true for rehash if the
		// password was invalid so that a client
		// that doesn't first check valid won't
		// allow an invalid password to be rehashed
		// over a valid one.
		//
		// This is done on both the server and
		// client to ensure that this condition is
		// always maintained.
		Rehash: rehash && valid,
	}, nil
}

// ServerOption allows changing the behaviour of the server.
type ServerOption func(*Server)

// WithRehashFunc changes the callback used to determine
// if a password should be rehashed or not. If fn is nil,
// the rehash result will always be false.
//
// By default, rehash will be true if the memory usage has
// increased.
func WithRehashFunc(fn func(ctx context.Context, time, memory uint32, threads uint8) bool) ServerOption {
	return func(s *Server) {
		s.rehash = fn
	}
}

// WithDOSProtectionFunc allows setting a callback to
// reject password verification when the hash has too high
// a work cost.
//
// The callback should return false to reject the the hash.
// By default all password verification will be accepted.
func WithDOSProtectionFunc(fn func(ctx context.Context, time, memory uint32, threads uint8) bool) ServerOption {
	return func(s *Server) {
		s.dosProt = fn
	}
}
