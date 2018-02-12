package portunes

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "unsafe" // for go:linkname

	pb "github.com/tmthrgd/portunes/internal/proto"
	_ "golang.org/x/crypto/argon2" // for argon2_deriveKey
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

//go:linkname argon2_deriveKey github.com/tmthrgd/portunes/vendor/golang.org/x/crypto/argon2.deriveKey
func argon2_deriveKey(mode int, password, salt, secret, data []byte, time, memory uint32, threads uint8, keyLen uint32) []byte

type server struct{}

func AttachServer(s *grpc.Server) {
	pb.RegisterPortunesServer(s, server{})
}

func (server) Hash(ctx context.Context, req *pb.HashRequest) (*pb.HashResponse, error) {
	salt := make([]byte, paramsCur.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	hash := argon2_deriveKey(int(paramsCur.Variant),
		[]byte(req.GetPassword()), salt,
		req.GetKey(), req.GetData(),
		paramsCur.Passes, paramsCur.Memory,
		paramsCur.Lanes, uint32(paramsCur.HashLen))

	return &pb.HashResponse{
		Hash: &pb.Hash{
			Version: paramsCur.Version,
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

	params, ok := paramsMap[hash.GetVersion()]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "invalid version")
	}

	expect := argon2_deriveKey(int(params.Variant),
		[]byte(req.GetPassword()), hash.GetSalt(),
		req.GetKey(), req.GetData(),
		params.Passes, params.Memory,
		params.Lanes, uint32(params.HashLen))

	valid := subtle.ConstantTimeCompare(expect, hash.GetHash()) == 1

	return &pb.VerifyResponse{
		Valid:  valid,
		Rehash: params.Rehash,
	}, nil
}
