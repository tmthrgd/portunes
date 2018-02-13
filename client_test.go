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
	AttachServer(srv)

	go func() {
		if err := srv.Serve(ln); err != nil {
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
	c, stop := testingClient()
	defer stop()

	c = c.WithSalt([]byte("🔑📋"))

	hash, err := c.Hash(context.Background(), "password🔐🔓")
	require.NoError(t, err)

	t.Logf("%d:%02x", len(hash), hash)
}

func TestVerify(t *testing.T) {
	c, stop := testingClient()
	defer stop()

	c = c.WithSalt([]byte("🔑📋"))

	hash, err := c.Hash(context.Background(), "password🔐🔓")
	require.NoError(t, err)

	t.Logf("%d:%02x", len(hash), hash)

	valid, rehash, err := c.Verify(context.Background(), "password🔐🔓", hash)
	require.NoError(t, err)

	assert.True(t, valid, "valid")
	assert.False(t, rehash, "rehash")
}

func TestWrongPassword(t *testing.T) {
	c, stop := testingClient()
	defer stop()

	c = c.WithSalt([]byte("🔑📋"))

	hash, err := c.Hash(context.Background(), "password🔐🔓")
	require.NoError(t, err)

	t.Logf("%d:%02x", len(hash), hash)

	assert.NoError(t, quick.Check(func(password string) bool {
		valid, _, err := c.Verify(context.Background(), password, hash)
		require.NoError(t, err)
		return !valid
	}, &quick.Config{
		MaxCountScale: 0.05,
	}))
}

func TestWrongSalt(t *testing.T) {
	c, stop := testingClient()
	defer stop()

	c = c.WithSalt([]byte("🔑📋"))

	hash, err := c.Hash(context.Background(), "password🔐🔓")
	require.NoError(t, err)

	t.Logf("%d:%02x", len(hash), hash)

	assert.NoError(t, quick.Check(func(salt []byte) bool {
		valid, _, err := c.WithSalt(salt).Verify(context.Background(), "password🔐🔓", hash)
		require.NoError(t, err)
		return !valid
	}, &quick.Config{
		MaxCountScale: 0.05,
	}))
}

func TestRandom(t *testing.T) {
	c, stop := testingClient()
	defer stop()

	assert.NoError(t, quick.Check(func(password string, salt []byte) bool {
		cc := c.WithSalt(salt)

		hash, err := cc.Hash(context.Background(), password)
		require.NoError(t, err)

		valid, _, err := cc.Verify(context.Background(), password, hash)
		require.NoError(t, err)
		return valid
	}, &quick.Config{
		MaxCountScale: 0.025,
	}))
}

func TestLongPassword(t *testing.T) {
	c, stop := testingClient()
	defer stop()

	c = c.WithSalt([]byte("🔑📋"))

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
			password := "password🔐🔓"
			password = strings.Repeat(password, tcase.size/len(password)+1)
			password = password[:tcase.size]

			hash, err := c.Hash(context.Background(), password)
			require.NoError(t, err)

			t.Logf("%d:%02x", len(hash), hash)

			valid, rehash, err := c.Verify(context.Background(), password, hash)
			require.NoError(t, err)

			assert.True(t, valid, "valid")
			assert.False(t, rehash, "rehash")
		})
	}
}

var testVectors = []struct {
	password, salt, hash string
	valid, rehash        bool
}{
	{"password🔐🔓", "🔑📋", "005587e939e96775433bd639e73d2c1cb298f55073d34d19d6375f888702402aa4", true, false},
}

func TestVectors(t *testing.T) {
	c, stop := testingClient()
	defer stop()

	for i, vector := range testVectors {
		vector := vector // capture range variable

		hash, err := hex.DecodeString(vector.hash)
		require.NoError(t, err, "invalid test vector hash")

		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			valid, rehash, err := c.WithSalt([]byte(vector.salt)).Verify(context.Background(), vector.password, hash)
			require.NoError(t, err)
			assert.Equal(t, vector.valid, valid, "valid")
			assert.Equal(t, vector.rehash, rehash, "rehash")
		})
	}
}

func BenchmarkHash(b *testing.B) {
	c, stop := testingClient()
	defer stop()

	c = c.WithSalt([]byte("🔑📋"))

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		_, err := c.Hash(context.Background(), "password🔐🔓")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHashParallel(b *testing.B) {
	c, stop := testingClient()
	defer stop()

	c = c.WithSalt([]byte("🔑📋"))

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := c.Hash(context.Background(), "password🔐🔓")
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkVerify(b *testing.B) {
	c, stop := testingClient()
	defer stop()

	c = c.WithSalt([]byte("🔑📋"))

	hash, err := c.Hash(context.Background(), "password🔐🔓")
	require.NoError(b, err)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		_, _, err := c.Verify(context.Background(), "password🔐🔓", hash)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyParallel(b *testing.B) {
	c, stop := testingClient()
	defer stop()

	c = c.WithSalt([]byte("🔑📋"))

	hash, err := c.Hash(context.Background(), "password🔐🔓")
	require.NoError(b, err)

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, err := c.Verify(context.Background(), "password🔐🔓", hash)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
