package portunes

import (
	"context"
	"crypto/rand"
	"crypto/subtle"

	pb "github.com/tmthrgd/portunes/internal/proto"
	"golang.org/x/crypto/argon2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server represents a portunes.Hasher service.
type Server struct {
	time, memory uint32
	threads      uint8
}

// NewServer creates an empty Server.
func NewServer(time, memory uint32, threads uint8) *Server {
	if time < 1 || threads < 1 {
		panic("portunes: invalid argon2 paramaters")
	}

	return &Server{time, memory, threads}
}

type hasherServer struct{ *Server }

// Attach registers the portunes.Hasher service to the
// given grpc.Server.
func (s *Server) Attach(srv *grpc.Server) {
	pb.RegisterHasherServer(srv, hasherServer{s})
}

func (s hasherServer) Hash(ctx context.Context, req *pb.HashRequest) (*pb.HashResponse, error) {
	salt := make([]byte, 16, 16+len(req.GetPepper()))
	if _, err := rand.Read(salt); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	hash := argon2.IDKey(
		[]byte(req.GetPassword()),
		append(salt, req.GetPepper()...),
		s.time, s.memory, s.threads, 16)

	res := make([]byte, 0, maxParamsLength+len(salt)+len(hash))
	res = appendParams(res, s.time, s.memory, s.threads)
	res = append(res, salt...)
	res = append(res, hash...)

	return &pb.HashResponse{
		Hash: res,
	}, nil
}

func (hasherServer) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	time, memory, threads, hash := consumeParams(req.GetHash())
	if len(hash) != 16+16 {
		return nil, status.Error(codes.InvalidArgument, "invalid hash")
	}

	salt, hash := hash[:16:16], hash[16:]

	expect := argon2.IDKey(
		[]byte(req.GetPassword()),
		append(salt, req.GetPepper()...),
		time, memory, threads, 16)

	valid := subtle.ConstantTimeCompare(expect, hash) == 1

	return &pb.VerifyResponse{
		Valid:  valid,
		Rehash: false, // TODO: implement
	}, nil
}
