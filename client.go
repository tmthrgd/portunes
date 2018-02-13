package portunes

import (
	"context"

	pb "github.com/tmthrgd/portunes/internal/proto"
	"google.golang.org/grpc"
)

type Client struct {
	cc *grpc.ClientConn
	pc pb.HasherClient

	salt []byte
}

func NewClient(cc *grpc.ClientConn) *Client {
	return &Client{
		cc: cc,
		pc: pb.NewHasherClient(cc),
	}
}

func (c *Client) WithSalt(salt []byte) *Client {
	cc := new(Client)
	*cc = *c
	cc.salt = append([]byte(nil), salt...)
	return cc
}

func (c *Client) Close() error {
	return c.cc.Close()
}

func (c *Client) Hash(ctx context.Context, password string, opts ...grpc.CallOption) ([]byte, error) {
	resp, err := c.pc.Hash(ctx, &pb.HashRequest{
		Password: password,
		Salt:     c.salt,
	}, opts...)
	if err != nil {
		return nil, err
	}

	return resp.GetHash(), nil
}

func (c *Client) Verify(ctx context.Context, password string, hash []byte, opts ...grpc.CallOption) (valid, rehash bool, err error) {
	resp, err := c.pc.Verify(ctx, &pb.VerifyRequest{
		Password: password,
		Salt:     c.salt,
		Hash:     hash,
	}, opts...)
	if err != nil {
		return false, false, err
	}

	return resp.GetValid(), resp.GetRehash(), nil
}
