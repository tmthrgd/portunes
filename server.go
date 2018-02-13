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

type server struct{}

// AttachServer registers the portunes.Hasher service to the
// given grpc.Server.
func AttachServer(s *grpc.Server) {
	pb.RegisterHasherServer(s, server{})
}

func (server) Hash(ctx context.Context, req *pb.HashRequest) (*pb.HashResponse, error) {
	params := &paramsList[paramsCurIdx]

	salt := make([]byte, params.SaltLen, params.SaltLen+len(req.GetPepper()))
	if _, err := rand.Read(salt); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	hash := argon2.IDKey(
		[]byte(req.GetPassword()),
		append(salt, req.GetPepper()...),
		params.Passes,
		params.Memory,
		params.Lanes,
		uint32(params.HashLen))

	const maxVarintBytes = 10
	res := make([]byte, 0, maxVarintBytes+len(salt)+len(hash))

	res = append(res, proto.EncodeVarint(uint64(paramsCurIdx))...)
	res = append(res, salt...)
	res = append(res, hash...)

	return &pb.HashResponse{
		Hash: res,
	}, nil
}

func (server) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
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

	if len(hash) != params.SaltLen+params.HashLen {
		return nil, status.Error(codes.InvalidArgument, "invalid hash")
	}

	salt, hash := hash[:params.SaltLen:params.SaltLen],
		hash[params.SaltLen:]

	expect := argon2.IDKey(
		[]byte(req.GetPassword()),
		append(salt, req.GetPepper()...),
		params.Passes,
		params.Memory,
		params.Lanes,
		uint32(params.HashLen))

	valid := subtle.ConstantTimeCompare(expect, hash) == 1

	return &pb.VerifyResponse{
		Valid:  valid,
		Rehash: params.Rehash,
	}, nil
}
