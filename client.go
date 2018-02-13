package portunes

import (
	"context"

	pb "github.com/tmthrgd/portunes/internal/proto"
	"google.golang.org/grpc"
)

// Client wraps a grpc.ClientConn for use with the
// portunes.Hasher service.
type Client struct {
	cc *grpc.ClientConn
	pc pb.HasherClient
}

// NewClient creates a Client from a given grpc.ClientConn.
func NewClient(cc *grpc.ClientConn) *Client {
	return &Client{
		cc: cc,
		pc: pb.NewHasherClient(cc),
	}
}

// Close calls Close on the underlying grpc.ClientConn.
func (c *Client) Close() error {
	return c.cc.Close()
}

// Hash derives a hash representing a given password and
// salt. It can later be passed into Verify to be checked
// for correctness.
//
// salt may be nil and is not needed for uniqueness as the
// given hash will have a random salt prepended by the
// server.
//
// opts can be used to provide grpc.CallOption's to the
// underlying connection.
func (c *Client) Hash(ctx context.Context, password string, salt []byte, opts ...grpc.CallOption) ([]byte, error) {
	resp, err := c.pc.Hash(ctx, &pb.HashRequest{
		Password: password,
		Salt:     salt,
	}, opts...)
	if err != nil {
		return nil, err
	}

	return resp.GetHash(), nil
}

// Verify determines whether the given password and salt
// match the provided hash (which must come from a previous
// call to Hash).
//
// salt should be as provided to the previous call to Hash.
//
// opts can be used to provide grpc.CallOption's to the
// underlying connection.
func (c *Client) Verify(ctx context.Context, password string, salt, hash []byte, opts ...grpc.CallOption) (valid, rehash bool, err error) {
	resp, err := c.pc.Verify(ctx, &pb.VerifyRequest{
		Password: password,
		Salt:     salt,
		Hash:     hash,
	}, opts...)
	if err != nil {
		return false, false, err
	}

	return resp.GetValid(), resp.GetRehash(), nil
}
