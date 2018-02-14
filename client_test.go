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
)

func testingClient() (c *Client, stop func()) {
	ln := memlistener.NewMemoryListener()

	srv := grpc.NewServer()
	NewServer(1, 64*1024, 2).Attach(srv)

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

	return NewClient(cc), func() {
		cc.Close()
		srv.Stop()
		ln.Close()
	}
}

func TestHash(t *testing.T) {
	t.Parallel()

	c, stop := testingClient()
	defer stop()

	hash, err := c.Hash(context.Background(), "password🔐🔓", []byte("🔑📋"))
	require.NoError(t, err)

	t.Logf("%d:%02x", len(hash), hash)
}

func TestVerify(t *testing.T) {
	t.Parallel()

	c, stop := testingClient()
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

	c, stop := testingClient()
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

	c, stop := testingClient()
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

	c, stop := testingClient()
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

			c, stop := testingClient()
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

	c, stop := testingClient()
	defer stop()

	hash1, err := c.Hash(context.Background(), "password🔐🔓", []byte("🔑📋"))
	require.NoError(t, err)

	hash2, err := c.Hash(context.Background(), "password🔐🔓", []byte("🔑📋"))
	require.NoError(t, err)

	assert.NotEqual(t, hash1, hash2, "Hash outputs should be unique")
}

func TestEmptyPassword(t *testing.T) {
	t.Parallel()

	c, stop := testingClient()
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

	c, stop := testingClient()
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
	{"password🔐🔓", "🔑📋", "0201a040fa69802700907ba1bf2887cb5be9aa9850365d0d2e0a973ac5da63153c7b", true, false},
	{"password🔐🔓", "🔑📋", "42085587e939e96775433bd639e73d2c1cb298f55073d34d19d6375f888702402aa4", true, false},
}

func TestVectors(t *testing.T) {
	t.Parallel()

	for i, vector := range testVectors {
		vector := vector // capture range variable

		hash, err := hex.DecodeString(vector.hash)
		require.NoError(t, err, "invalid test vector hash")

		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			t.Parallel()

			c, stop := testingClient()
			defer stop()

			valid, rehash, err := c.Verify(context.Background(), vector.password, []byte(vector.pepper), hash)
			require.NoError(t, err)
			assert.Equal(t, vector.valid, valid, "valid")
			assert.Equal(t, vector.rehash, rehash, "rehash")
		})
	}
}

func BenchmarkHash(b *testing.B) {
	c, stop := testingClient()
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
	c, stop := testingClient()
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
	c, stop := testingClient()
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
	c, stop := testingClient()
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
