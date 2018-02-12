package portunes

import (
	"context"

	"github.com/golang/protobuf/proto"
	pb "github.com/tmthrgd/portunes/internal/proto"
	"google.golang.org/grpc"
)

type Client struct {
	cc *grpc.ClientConn
	pc pb.PortunesClient

	key, data []byte
}

func NewClient(cc *grpc.ClientConn) *Client {
	return &Client{
		cc: cc,
		pc: pb.NewPortunesClient(cc),
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

	return proto.Marshal(resp.GetHash())
}

func (c *Client) Verify(ctx context.Context, password string, hash []byte, opts ...grpc.CallOption) (valid, rehash bool, err error) {
	var msg pb.Hash
	if err := proto.Unmarshal(hash, &msg); err != nil {
		return false, false, err
	}

	resp, err := c.pc.Verify(ctx, &pb.VerifyRequest{
		Password: password,
		Key:      c.key,
		Data:     c.data,
		Hash:     &msg,
	}, opts...)
	if err != nil {
		return false, false, err
	}

	return resp.GetValid(), resp.GetRehash(), nil
}
