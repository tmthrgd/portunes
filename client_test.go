package portunes

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"
	"testing/quick"
	"time"

	"github.com/hydrogen18/memlistener"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func testingClient(sopt ...ServerOption) (c *Client, s *Server, stop func()) {
	ln := memlistener.NewMemoryListener()

	srv := grpc.NewServer()

	s = NewServer(1, 64*1024, 2, sopt...)
	s.Attach(srv)

	go func() {
		if err := srv.Serve(ln); err != nil && err != grpc.ErrServerStopped {
			panic(err)
		}
	}()

	cc, err := grpc.Dial("",
		grpc.WithDialer(func(addr string, dl time.Duration) (net.Conn, error) {
			return ln.Dial("test", addr)
		}),
		grpc.WithInsecure(),
	)
	if err != nil {
		panic(err)
	}

	return NewClient(cc), s, func() {
		cc.Close()
		srv.Stop()
		ln.Close()
	}
}

func TestHash(t *testing.T) {
	t.Parallel()

	c, _, stop := testingClient()
	defer stop()

	hash, err := c.Hash(context.Background(), "password🔐🔓", []byte("🔑📋"))
	require.NoError(t, err)

	t.Logf("%d:%02x", len(hash), hash)
}

func TestVerify(t *testing.T) {
	t.Parallel()

	c, _, stop := testingClient()
	defer stop()

	hash, err := c.Hash(context.Background(), "password🔐🔓", []byte("🔑📋"))
	require.NoError(t, err)

	t.Logf("%d:%02x", len(hash), hash)

	valid, rehash, err := c.Verify(context.Background(), "password🔐🔓", []byte("🔑📋"), hash)
	require.NoError(t, err)

	assert.True(t, valid, "valid")
	assert.False(t, rehash, "rehash")
}

func TestWrongPassword(t *testing.T) {
	t.Parallel()

	c, _, stop := testingClient()
	defer stop()

	hash, err := c.Hash(context.Background(), "password🔐🔓", []byte("🔑📋"))
	require.NoError(t, err)

	t.Logf("%d:%02x", len(hash), hash)

	assert.NoError(t, quick.Check(func(password string) bool {
		valid, _, err := c.Verify(context.Background(), password, []byte("🔑📋"), hash)
		require.NoError(t, err)
		return !valid
	}, &quick.Config{
		MaxCountScale: 0.05,
	}))
}

func TestWrongPepper(t *testing.T) {
	t.Parallel()

	c, _, stop := testingClient()
	defer stop()

	hash, err := c.Hash(context.Background(), "password🔐🔓", []byte("🔑📋"))
	require.NoError(t, err)

	t.Logf("%d:%02x", len(hash), hash)

	assert.NoError(t, quick.Check(func(pepper []byte) bool {
		valid, _, err := c.Verify(context.Background(), "password🔐🔓", pepper, hash)
		require.NoError(t, err)
		return !valid
	}, &quick.Config{
		MaxCountScale: 0.05,
	}))
}

func TestRandom(t *testing.T) {
	t.Parallel()

	c, _, stop := testingClient()
	defer stop()

	assert.NoError(t, quick.Check(func(password string, pepper []byte) bool {
		hash, err := c.Hash(context.Background(), password, pepper)
		require.NoError(t, err)

		valid, _, err := c.Verify(context.Background(), password, pepper, hash)
		require.NoError(t, err)
		return valid
	}, &quick.Config{
		MaxCountScale: 0.025,
	}))
}

func TestLongPassword(t *testing.T) {
	t.Parallel()

	for _, tcase := range []struct {
		name string
		size int
	}{
		{"1KiB", 1 << 10},
		{"1MiB", 1 << 20},
		{"3MiB", 3 << 20},
	} {
		tcase := tcase // capture range variable

		t.Run(tcase.name, func(t *testing.T) {
			t.Parallel()

			c, _, stop := testingClient()
			defer stop()

			password := "password🔐🔓"
			password = strings.Repeat(password, tcase.size/len(password)+1)
			password = password[:tcase.size]

			hash, err := c.Hash(context.Background(), password, []byte("🔑📋"))
			require.NoError(t, err)

			t.Logf("%d:%02x", len(hash), hash)

			valid, rehash, err := c.Verify(context.Background(), password, []byte("🔑📋"), hash)
			require.NoError(t, err)

			assert.True(t, valid, "valid")
			assert.False(t, rehash, "rehash")
		})
	}
}

func TestHashUnique(t *testing.T) {
	t.Parallel()

	c, _, stop := testingClient()
	defer stop()

	hash1, err := c.Hash(context.Background(), "password🔐🔓", []byte("🔑📋"))
	require.NoError(t, err)

	hash2, err := c.Hash(context.Background(), "password🔐🔓", []byte("🔑📋"))
	require.NoError(t, err)

	assert.NotEqual(t, hash1, hash2, "Hash outputs should be unique")
}

func TestEmptyPassword(t *testing.T) {
	t.Parallel()

	c, _, stop := testingClient()
	defer stop()

	hash, err := c.Hash(context.Background(), "", []byte("🔑📋"))
	require.NoError(t, err)

	t.Logf("%d:%02x", len(hash), hash)

	valid, rehash, err := c.Verify(context.Background(), "", []byte("🔑📋"), hash)
	require.NoError(t, err)

	assert.True(t, valid, "valid")
	assert.False(t, rehash, "rehash")
}

func TestEmptyPepper(t *testing.T) {
	t.Parallel()

	c, _, stop := testingClient()
	defer stop()

	hash, err := c.Hash(context.Background(), "password🔐🔓", nil)
	require.NoError(t, err)

	t.Logf("%d:%02x", len(hash), hash)

	valid, rehash, err := c.Verify(context.Background(), "password🔐🔓", nil, hash)
	require.NoError(t, err)

	assert.True(t, valid, "valid")
	assert.False(t, rehash, "rehash")
}

var testVectors = []struct {
	password, pepper, hash string
	valid, rehash          bool
}{
	{"password🔐🔓", "🔑📋", "020001a040fa69802700907ba1bf2887cb5be9aa9850365d0d2e0a973ac5da63153c7b", true, false},
	{"password🔐🔓", "🔑📋", "0202085587e939e96775433bd639e73d2c1cb298f55073d34d19d6375f888702402aa4", true, false},
	{"password🔐🔓", "🔑📋", "0200808080800895cebbae3206cf7b9087862110a2cf66618df34c4a88dfa9da279e0d3c6ee660", true, true},
}

func TestVectors(t *testing.T) {
	t.Parallel()

	for i, vector := range testVectors {
		vector := vector // capture range variable

		hash, err := hex.DecodeString(vector.hash)
		require.NoError(t, err, "invalid test vector hash")

		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			t.Parallel()

			c, _, stop := testingClient()
			defer stop()

			valid, rehash, err := c.Verify(context.Background(), vector.password, []byte(vector.pepper), hash)
			require.NoError(t, err)
			assert.Equal(t, vector.valid, valid, "valid")
			assert.Equal(t, vector.rehash, rehash, "rehash")
		})
	}
}

func TestRehash(t *testing.T) {
	t.Parallel()

	c, _, stop := testingClient()
	defer stop()

	hash, err := c.Hash(context.Background(), "password🔐🔓", []byte("🔑📋"))
	require.NoError(t, err)

	t.Logf("%d:%02x", len(hash), hash)

	rehashFn := func(rehash bool) func(uint32, uint32, uint8) bool {
		return func(uint32, uint32, uint8) bool {
			return rehash
		}
	}

	for _, tc := range []struct {
		fn     func(uint32, uint32, uint8) bool
		rehash bool
	}{
		{nil, false},
		{rehashFn(false), false},
		{rehashFn(true), true},
	} {
		c, _, stop := testingClient(WithRehashFunc(tc.fn))
		defer stop()

		valid, rehash, err := c.Verify(context.Background(), "password🔐🔓", []byte("🔑📋"), hash)
		require.NoError(t, err)

		assert.True(t, valid, "valid")
		assert.Equal(t, tc.rehash, rehash, "rehash")
	}
}

func TestDefaultRehash(t *testing.T) {
	t.Parallel()

	c, s, stop := testingClient()
	defer stop()

	s.SetParameters(1, 64*1024, 1)

	hash, err := c.Hash(context.Background(), "password🔐🔓", []byte("🔑📋"))
	require.NoError(t, err)

	t.Logf("%d:%02x", len(hash), hash)

	s.SetParameters(1, 128*1024, 1)

	valid, rehash, err := c.Verify(context.Background(), "password🔐🔓", []byte("🔑📋"), hash)
	require.NoError(t, err)

	assert.True(t, valid, "valid")
	assert.True(t, rehash, "rehash")
}

func TestDOSProtection(t *testing.T) {
	t.Parallel()

	c, _, stop := testingClient()
	defer stop()

	hash, err := c.Hash(context.Background(), "password🔐🔓", []byte("🔑📋"))
	require.NoError(t, err)

	t.Logf("%d:%02x", len(hash), hash)

	dosProtFn := func(allow bool) func(uint32, uint32, uint8) bool {
		return func(uint32, uint32, uint8) bool {
			return allow
		}
	}

	for _, tc := range []struct {
		fn    func(uint32, uint32, uint8) bool
		allow bool
	}{
		{nil, true},
		{dosProtFn(false), false},
		{dosProtFn(true), true},
	} {
		c, _, stop := testingClient(WithDOSProtectionFunc(tc.fn))
		defer stop()

		valid, rehash, err := c.Verify(context.Background(), "password🔐🔓", []byte("🔑📋"), hash)

		if tc.allow {
			require.NoError(t, err)

			assert.True(t, valid, "valid")
			assert.False(t, rehash, "rehash")
		} else {
			require.Error(t, err)

			assert.Equal(t, codes.ResourceExhausted, status.Code(err), "invalid gRPC status code")
		}
	}
}

func BenchmarkHash(b *testing.B) {
	c, _, stop := testingClient()
	defer stop()

	pepper := []byte("🔑📋")

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		_, err := c.Hash(context.Background(), "password🔐🔓", pepper)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHashParallel(b *testing.B) {
	c, _, stop := testingClient()
	defer stop()

	pepper := []byte("🔑📋")

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := c.Hash(context.Background(), "password🔐🔓", pepper)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkVerify(b *testing.B) {
	c, _, stop := testingClient()
	defer stop()

	pepper := []byte("🔑📋")

	hash, err := c.Hash(context.Background(), "password🔐🔓", pepper)
	require.NoError(b, err)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		_, _, err := c.Verify(context.Background(), "password🔐🔓", pepper, hash)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyParallel(b *testing.B) {
	c, _, stop := testingClient()
	defer stop()

	pepper := []byte("🔑📋")

	hash, err := c.Hash(context.Background(), "password🔐🔓", pepper)
	require.NoError(b, err)

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, err := c.Verify(context.Background(), "password🔐🔓", pepper, hash)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
