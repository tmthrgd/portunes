package portunes

import (
	"context"

	pb "go.tmthrgd.dev/portunes/internal/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
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
// pepper. It can later be passed into Verify to be checked
// for correctness.
//
// pepper may be nil and is not needed for uniqueness as
// the given hash will have a random salt prepended by the
// server.
//
// opts can be used to provide grpc.CallOption's to the
// underlying connection.
func (c *Client) Hash(ctx context.Context, password string, pepper []byte, opts ...grpc.CallOption) ([]byte, error) {
	resp, err := c.pc.Hash(ctx, &pb.HashRequest{
		Password: password,
		Pepper:   pepper,
	}, disableCompression(opts)...)
	if err != nil {
		return nil, err
	}

	return resp.Hash, nil
}

// Verify determines whether the given password and pepper
// match the provided hash (which must come from a previous
// call to Hash).
//
// pepper should be as provided to the previous call to
// Hash.
//
// opts can be used to provide grpc.CallOption's to the
// underlying connection.
func (c *Client) Verify(ctx context.Context, password string, pepper, hash []byte, opts ...grpc.CallOption) (valid, rehash bool, err error) {
	resp, err := c.pc.Verify(ctx, &pb.VerifyRequest{
		Password: password,
		Pepper:   pepper,
		Hash:     hash,
	}, disableCompression(opts)...)
	if err != nil {
		return false, false, err
	}

	// Never return true for rehash if the password was
	// invalid so that a caller that doesn't first
	// check valid won't allow an invalid password to
	// be rehashed over a valid one.
	//
	// This is done on both the server and client to
	// ensure that this condition is always maintained.
	return resp.Valid, resp.Rehash && resp.Valid, nil
}

// disableCompression does what it says on the tin. It's
// used to ensure the underlying transport does not
// introduce any compression side-channels. Otherwise it
// would be possible to recover the pepper by manipulating
// the password, or to learn information about the password,
// by watching packet sizes on the wire.
func disableCompression(opts []grpc.CallOption) []grpc.CallOption {
	return append(opts, grpc.UseCompressor(encoding.Identity))
}
