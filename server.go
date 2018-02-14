package portunes

import (
	"context"
	"crypto/rand"
	"crypto/subtle"

	"github.com/golang/protobuf/proto"
	pb "github.com/tmthrgd/portunes/internal/proto"
	"golang.org/x/crypto/argon2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server represents a portunes.Hasher service.
type Server struct{}

// NewServer creates an empty Server.
func NewServer() *Server {
	return new(Server)
}

type hasherServer struct{ *Server }

// Attach registers the portunes.Hasher service to the
// given grpc.Server.
func (s *Server) Attach(srv *grpc.Server) {
	pb.RegisterHasherServer(srv, hasherServer{s})
}

func (hasherServer) Hash(ctx context.Context, req *pb.HashRequest) (*pb.HashResponse, error) {
	params := &paramsList[paramsCurIdx]

	salt := make([]byte, 16, 16+len(req.GetPepper()))
	if _, err := rand.Read(salt); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	hash := argon2.IDKey(
		[]byte(req.GetPassword()),
		append(salt, req.GetPepper()...),
		params.Passes, params.Memory,
		params.Lanes, 16)

	const maxVarintBytes = 10
	res := make([]byte, 0, maxVarintBytes+len(salt)+len(hash))

	res = append(res, proto.EncodeVarint(uint64(paramsCurIdx))...)
	res = append(res, salt...)
	res = append(res, hash...)

	return &pb.HashResponse{
		Hash: res,
	}, nil
}

func (hasherServer) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	hash := req.GetHash()
	if hash == nil {
		return nil, status.Error(codes.InvalidArgument, "missing hash")
	}

	version, n := proto.DecodeVarint(hash)
	hash = hash[n:]

	if version >= uint64(len(paramsList)) || n == 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid hash")
	}

	params := &paramsList[version]

	if len(hash) != 16+16 {
		return nil, status.Error(codes.InvalidArgument, "invalid hash")
	}

	salt, hash := hash[:16:16], hash[16:]

	expect := argon2.IDKey(
		[]byte(req.GetPassword()),
		append(salt, req.GetPepper()...),
		params.Passes, params.Memory,
		params.Lanes, 16)

	valid := subtle.ConstantTimeCompare(expect, hash) == 1

	return &pb.VerifyResponse{
		Valid:  valid,
		Rehash: params.Rehash,
	}, nil
}
