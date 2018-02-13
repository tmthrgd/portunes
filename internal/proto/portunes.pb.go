// Code generated by protoc-gen-go. DO NOT EDIT.
// source: portunes.proto

/*
Package proto is a generated protocol buffer package.

It is generated from these files:
	portunes.proto

It has these top-level messages:
	HashRequest
	HashResponse
	VerifyRequest
	VerifyResponse
*/
package proto

import proto1 "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto1.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto1.ProtoPackageIsVersion2 // please upgrade the proto package

type HashRequest struct {
	Password string `protobuf:"bytes,1,opt,name=password" json:"password,omitempty"`
	Key      []byte `protobuf:"bytes,2,opt,name=key,proto3" json:"key,omitempty"`
	Data     []byte `protobuf:"bytes,3,opt,name=data,proto3" json:"data,omitempty"`
}

func (m *HashRequest) Reset()                    { *m = HashRequest{} }
func (m *HashRequest) String() string            { return proto1.CompactTextString(m) }
func (*HashRequest) ProtoMessage()               {}
func (*HashRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *HashRequest) GetPassword() string {
	if m != nil {
		return m.Password
	}
	return ""
}

func (m *HashRequest) GetKey() []byte {
	if m != nil {
		return m.Key
	}
	return nil
}

func (m *HashRequest) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

type HashResponse struct {
	Hash []byte `protobuf:"bytes,1,opt,name=hash,proto3" json:"hash,omitempty"`
}

func (m *HashResponse) Reset()                    { *m = HashResponse{} }
func (m *HashResponse) String() string            { return proto1.CompactTextString(m) }
func (*HashResponse) ProtoMessage()               {}
func (*HashResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *HashResponse) GetHash() []byte {
	if m != nil {
		return m.Hash
	}
	return nil
}

type VerifyRequest struct {
	Password string `protobuf:"bytes,1,opt,name=password" json:"password,omitempty"`
	Key      []byte `protobuf:"bytes,2,opt,name=key,proto3" json:"key,omitempty"`
	Data     []byte `protobuf:"bytes,3,opt,name=data,proto3" json:"data,omitempty"`
	Hash     []byte `protobuf:"bytes,4,opt,name=hash,proto3" json:"hash,omitempty"`
}

func (m *VerifyRequest) Reset()                    { *m = VerifyRequest{} }
func (m *VerifyRequest) String() string            { return proto1.CompactTextString(m) }
func (*VerifyRequest) ProtoMessage()               {}
func (*VerifyRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *VerifyRequest) GetPassword() string {
	if m != nil {
		return m.Password
	}
	return ""
}

func (m *VerifyRequest) GetKey() []byte {
	if m != nil {
		return m.Key
	}
	return nil
}

func (m *VerifyRequest) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

func (m *VerifyRequest) GetHash() []byte {
	if m != nil {
		return m.Hash
	}
	return nil
}

type VerifyResponse struct {
	Valid  bool `protobuf:"varint,1,opt,name=valid" json:"valid,omitempty"`
	Rehash bool `protobuf:"varint,2,opt,name=rehash" json:"rehash,omitempty"`
}

func (m *VerifyResponse) Reset()                    { *m = VerifyResponse{} }
func (m *VerifyResponse) String() string            { return proto1.CompactTextString(m) }
func (*VerifyResponse) ProtoMessage()               {}
func (*VerifyResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *VerifyResponse) GetValid() bool {
	if m != nil {
		return m.Valid
	}
	return false
}

func (m *VerifyResponse) GetRehash() bool {
	if m != nil {
		return m.Rehash
	}
	return false
}

func init() {
	proto1.RegisterType((*HashRequest)(nil), "portunes.HashRequest")
	proto1.RegisterType((*HashResponse)(nil), "portunes.HashResponse")
	proto1.RegisterType((*VerifyRequest)(nil), "portunes.VerifyRequest")
	proto1.RegisterType((*VerifyResponse)(nil), "portunes.VerifyResponse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for Hasher service

type HasherClient interface {
	Hash(ctx context.Context, in *HashRequest, opts ...grpc.CallOption) (*HashResponse, error)
	Verify(ctx context.Context, in *VerifyRequest, opts ...grpc.CallOption) (*VerifyResponse, error)
}

type hasherClient struct {
	cc *grpc.ClientConn
}

func NewHasherClient(cc *grpc.ClientConn) HasherClient {
	return &hasherClient{cc}
}

func (c *hasherClient) Hash(ctx context.Context, in *HashRequest, opts ...grpc.CallOption) (*HashResponse, error) {
	out := new(HashResponse)
	err := grpc.Invoke(ctx, "/portunes.Hasher/Hash", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *hasherClient) Verify(ctx context.Context, in *VerifyRequest, opts ...grpc.CallOption) (*VerifyResponse, error) {
	out := new(VerifyResponse)
	err := grpc.Invoke(ctx, "/portunes.Hasher/Verify", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for Hasher service

type HasherServer interface {
	Hash(context.Context, *HashRequest) (*HashResponse, error)
	Verify(context.Context, *VerifyRequest) (*VerifyResponse, error)
}

func RegisterHasherServer(s *grpc.Server, srv HasherServer) {
	s.RegisterService(&_Hasher_serviceDesc, srv)
}

func _Hasher_Hash_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HashRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HasherServer).Hash(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/portunes.Hasher/Hash",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HasherServer).Hash(ctx, req.(*HashRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Hasher_Verify_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VerifyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HasherServer).Verify(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/portunes.Hasher/Verify",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HasherServer).Verify(ctx, req.(*VerifyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Hasher_serviceDesc = grpc.ServiceDesc{
	ServiceName: "portunes.Hasher",
	HandlerType: (*HasherServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Hash",
			Handler:    _Hasher_Hash_Handler,
		},
		{
			MethodName: "Verify",
			Handler:    _Hasher_Verify_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "portunes.proto",
}

func init() { proto1.RegisterFile("portunes.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 246 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x2b, 0xc8, 0x2f, 0x2a,
	0x29, 0xcd, 0x4b, 0x2d, 0xd6, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x80, 0xf1, 0x95, 0xfc,
	0xb9, 0xb8, 0x3d, 0x12, 0x8b, 0x33, 0x82, 0x52, 0x0b, 0x4b, 0x53, 0x8b, 0x4b, 0x84, 0xa4, 0xb8,
	0x38, 0x0a, 0x12, 0x8b, 0x8b, 0xcb, 0xf3, 0x8b, 0x52, 0x24, 0x18, 0x15, 0x18, 0x35, 0x38, 0x83,
	0xe0, 0x7c, 0x21, 0x01, 0x2e, 0xe6, 0xec, 0xd4, 0x4a, 0x09, 0x26, 0x05, 0x46, 0x0d, 0x9e, 0x20,
	0x10, 0x53, 0x48, 0x88, 0x8b, 0x25, 0x25, 0xb1, 0x24, 0x51, 0x82, 0x19, 0x2c, 0x04, 0x66, 0x2b,
	0x29, 0x71, 0xf1, 0x40, 0x0c, 0x2c, 0x2e, 0xc8, 0xcf, 0x2b, 0x4e, 0x05, 0xa9, 0xc9, 0x48, 0x2c,
	0xce, 0x00, 0x9b, 0xc6, 0x13, 0x04, 0x66, 0x2b, 0xa5, 0x72, 0xf1, 0x86, 0xa5, 0x16, 0x65, 0xa6,
	0x55, 0x52, 0xcd, 0x5a, 0xb8, 0x35, 0x2c, 0x48, 0xd6, 0xd8, 0x71, 0xf1, 0xc1, 0xac, 0x81, 0x3a,
	0x46, 0x84, 0x8b, 0xb5, 0x2c, 0x31, 0x27, 0x13, 0x62, 0x09, 0x47, 0x10, 0x84, 0x23, 0x24, 0xc6,
	0xc5, 0x56, 0x94, 0x0a, 0xd6, 0xcd, 0x04, 0x16, 0x86, 0xf2, 0x8c, 0x1a, 0x18, 0xb9, 0xd8, 0x40,
	0x7e, 0x49, 0x2d, 0x12, 0x32, 0xe7, 0x62, 0x01, 0xb1, 0x84, 0x44, 0xf5, 0xe0, 0x21, 0x89, 0x14,
	0x6c, 0x52, 0x62, 0xe8, 0xc2, 0x10, 0xfb, 0x94, 0x18, 0x84, 0x6c, 0xb9, 0xd8, 0x20, 0x6e, 0x10,
	0x12, 0x47, 0xa8, 0x41, 0xf1, 0xbc, 0x94, 0x04, 0xa6, 0x04, 0x4c, 0xbb, 0x13, 0xa7, 0x07, 0x63,
	0x14, 0x2b, 0x38, 0xce, 0x92, 0xd8, 0xc0, 0x94, 0x31, 0x20, 0x00, 0x00, 0xff, 0xff, 0xd3, 0xc2,
	0x09, 0x14, 0xcc, 0x01, 0x00, 0x00,
}
