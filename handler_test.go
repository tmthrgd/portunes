package portunes

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"testing/quick"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var dumpReqBody = true

func getHash(t *testing.T, hashURL *url.URL, password, key, ad string) []byte {
	start := time.Now()

	req, err := http.NewRequest(HashMethod, hashURL.String(), strings.NewReader(password))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Key", key)
	req.Header.Set("X-Associated-Data", ad)

	b, err := httputil.DumpRequestOut(req, dumpReqBody)
	require.NoError(t, err)

	fmt.Println("================")
	fmt.Printf("%s\n\n", b)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	b, err = httputil.DumpResponse(resp, false)
	require.NoError(t, err)

	fmt.Println("----------------")
	fmt.Printf("%s\n", b)

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("status code: %d", resp.StatusCode)
	}

	hash, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()

	fmt.Println(hex.Dump(hash))

	fmt.Printf("################ %s\n", time.Since(start))
	return hash
}

func verify(t *testing.T, verifyURL *url.URL, hash []byte, password, key, ad string) bool {
	start := time.Now()

	req, err := http.NewRequest(VerifyMethod, verifyURL.String(), io.MultiReader(bytes.NewReader(hash), strings.NewReader(password)))
	require.NoError(t, err)
	req.ContentLength = int64(len(hash) + len(password))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Key", key)
	req.Header.Set("X-Associated-Data", ad)

	b, err := httputil.DumpRequestOut(req, false)
	require.NoError(t, err)

	fmt.Println("================")
	fmt.Printf("%s\n\n", b)

	if dumpReqBody {
		var buf bytes.Buffer
		d := hex.Dumper(&buf)
		d.Write(hash)
		io.WriteString(d, password)
		d.Close()
		fmt.Println(buf.String())
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	b, err = httputil.DumpResponse(resp, true)
	require.NoError(t, err)

	fmt.Println("----------------")
	fmt.Printf("%s\n", b)

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusForbidden:
	default:
		require.Fail(t, resp.Status)
	}

	require.Equal(t, "0", resp.Header.Get("X-Rehash"), "invalid X-Rehash header")

	fmt.Printf("################ %s\n", time.Since(start))
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func TestPortunes(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle(HashPath, http.HandlerFunc(Hash))
	mux.Handle(VerifyPath, http.HandlerFunc(Verify))

	s := httptest.NewServer(mux)

	uri, err := url.Parse(s.URL)
	require.NoError(t, err)

	hashURL := *uri
	hashURL.Path = "/hash"

	verifyURL := *uri
	verifyURL.Path = "/verify"

	hash := getHash(t, &hashURL, "password🔐🔓", "🔑", "📋")
	assert.True(t, verify(t, &verifyURL, hash, "password🔐🔓", "🔑", "📋"))

	assert.NoError(t, quick.Check(func(password string) bool {
		return !verify(t, &verifyURL, hash, password, "🔑", "📋")
	}, &quick.Config{
		MaxCountScale: 0.1,
	}))

	assert.NoError(t, quick.Check(func(key string) bool {
		return !verify(t, &verifyURL, hash, "password🔐🔓", key, "📋")
	}, &quick.Config{
		MaxCountScale: 0.1,

		Values: func(values []reflect.Value, rand *rand.Rand) {
			key, ok := quick.Value(reflect.TypeOf(""), rand)
			if !ok {
				panic("quick.Value failed")
			}

			values[0] = key
		},
	}))

	assert.NoError(t, quick.Check(func(ad string) bool {
		return !verify(t, &verifyURL, hash, "password🔐🔓", "🔑", ad)
	}, &quick.Config{
		MaxCountScale: 0.1,
	}))

	assert.NoError(t, quick.Check(func(password, key, ad string) bool {
		hash := getHash(t, &hashURL, password, key, ad)
		return verify(t, &verifyURL, hash, password, key, ad)
	}, &quick.Config{
		MaxCountScale: 0.1,

		Values: func(values []reflect.Value, rand *rand.Rand) {
			for i := range values {
				var ok bool
				values[i], ok = quick.Value(reflect.TypeOf(""), rand)
				if !ok {
					panic("quick.Value failed")
				}
			}
		},
	}))

	password := "password🔐🔓"
	for len(password) < 1024 {
		password += password
	}

	hash = getHash(t, &hashURL, password, "🔑", "📋")
	assert.True(t, verify(t, &verifyURL, hash, password, "🔑", "📋"), "failed with long password")

	dumpReqBody = false

	for len(password) < 1048576 {
		password += password
	}

	hash = getHash(t, &hashURL, password, "🔑", "📋")
	assert.True(t, verify(t, &verifyURL, hash, password, "🔑", "📋"), "failed with long password")
}
