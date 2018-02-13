package portunes

import (
	"context"

	pb "github.com/tmthrgd/portunes/internal/proto"
	"google.golang.org/grpc"
)

type Client struct {
	cc *grpc.ClientConn
	pc pb.HasherClient

	key, data []byte
}

func NewClient(cc *grpc.ClientConn) *Client {
	return &Client{
		cc: cc,
		pc: pb.NewHasherClient(cc),
	}
}

func (c *Client) WithKey(key []byte) *Client {
	cc := new(Client)
	*cc = *c
	cc.key = append([]byte(nil), key...)
	return cc
}

func (c *Client) WithAssociatedData(data []byte) *Client {
	cc := new(Client)
	*cc = *c
	cc.data = append([]byte(nil), data...)
	return cc
}

func (c *Client) Close() error {
	return c.cc.Close()
}

func (c *Client) Hash(ctx context.Context, password string, opts ...grpc.CallOption) ([]byte, error) {
	resp, err := c.pc.Hash(ctx, &pb.HashRequest{
		Password: password,
		Key:      c.key,
		Data:     c.data,
	}, opts...)
	if err != nil {
		return nil, err
	}

	return resp.GetHash(), nil
}

func (c *Client) Verify(ctx context.Context, password string, hash []byte, opts ...grpc.CallOption) (valid, rehash bool, err error) {
	resp, err := c.pc.Verify(ctx, &pb.VerifyRequest{
		Password: password,
		Key:      c.key,
		Data:     c.data,
		Hash:     hash,
	}, opts...)
	if err != nil {
		return false, false, err
	}

	return resp.GetValid(), resp.GetRehash(), nil
}
