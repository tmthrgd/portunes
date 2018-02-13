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

type server struct{}

func AttachServer(s *grpc.Server) {
	pb.RegisterPortunesServer(s, server{})
}

func appendUint32(b []byte, x uint32) []byte {
	a := [4]byte{
		byte(x),
		byte(x >> 8),
		byte(x >> 16),
		byte(x >> 24),
	}
	return append(b, a[:]...)
}

func mergeSalt(salt, key, data []byte) []byte {
	res := make([]byte, 0, 4+len(salt)+4+len(key)+4+len(data))

	res = appendUint32(res, uint32(len(salt)))
	res = append(res, salt...)

	res = appendUint32(res, uint32(len(key)))
	res = append(res, key...)

	res = appendUint32(res, uint32(len(data)))
	res = append(res, data...)

	return res
}

func (server) Hash(ctx context.Context, req *pb.HashRequest) (*pb.HashResponse, error) {
	params := &paramsList[paramsCurIdx]

	salt := make([]byte, params.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	hash := argon2.IDKey(
		[]byte(req.GetPassword()),
		mergeSalt(salt,
			req.GetKey(),
			req.GetData()),
		params.Passes,
		params.Memory,
		params.Lanes,
		uint32(params.HashLen))

	return &pb.HashResponse{
		Hash: &pb.Hash{
			Version: uint32(paramsCurIdx),
			Salt:    salt,
			Hash:    hash,
		},
	}, nil
}

func (server) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	hash := req.GetHash()
	if hash == nil {
		return nil, status.Error(codes.InvalidArgument, "missing hash")
	}

	if hash.GetVersion() >= uint32(len(paramsList)) {
		return nil, status.Error(codes.InvalidArgument, "invalid version")
	}

	params := &paramsList[hash.GetVersion()]

	expect := argon2.IDKey(
		[]byte(req.GetPassword()),
		mergeSalt(hash.GetSalt(),
			req.GetKey(),
			req.GetData()),
		params.Passes,
		params.Memory,
		params.Lanes,
		uint32(params.HashLen))

	valid := subtle.ConstantTimeCompare(expect, hash.GetHash()) == 1

	return &pb.VerifyResponse{
		Valid:  valid,
		Rehash: params.Rehash,
	}, nil
}
