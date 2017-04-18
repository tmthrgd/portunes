// +build ignore

package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"reflect"
	"strings"
	"testing/quick"
	"time"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func getHash(hashURL *url.URL, password, key, ad string) []byte {
	req, err := http.NewRequest(http.MethodPost, hashURL.String(), strings.NewReader(password))
	must(err)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Key", key)
	req.Header.Set("X-Associated-Data", ad)

	b, err := httputil.DumpRequestOut(req, true)
	must(err)

	fmt.Println("================")
	fmt.Printf("%s\n\n", b)

	resp, err := http.DefaultClient.Do(req)
	must(err)

	b, err = httputil.DumpResponse(resp, false)
	must(err)

	fmt.Println("----------------")
	fmt.Printf("%s\n", b)

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("status code: %d", resp.StatusCode)
	}

	hash, err := ioutil.ReadAll(resp.Body)
	must(err)
	resp.Body.Close()

	fmt.Println(hex.Dump(hash))

	return hash
}

func verify(verifyURL *url.URL, hash []byte, password, key, ad string) bool {
	req, err := http.NewRequest(http.MethodPost, verifyURL.String(), io.MultiReader(bytes.NewReader(hash), strings.NewReader(password)))
	must(err)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Key", key)
	req.Header.Set("X-Associated-Data", ad)

	b, err := httputil.DumpRequestOut(req, false)
	must(err)

	fmt.Println("================")
	fmt.Printf("%s\n\n", b)

	var buf bytes.Buffer
	d := hex.Dumper(&buf)
	d.Write(hash)
	io.WriteString(d, password)
	d.Close()
	fmt.Println(buf.String())

	resp, err := http.DefaultClient.Do(req)
	must(err)

	b, err = httputil.DumpResponse(resp, true)
	must(err)

	fmt.Println("----------------")
	fmt.Printf("%s\n", b)

	switch resp.StatusCode {
	case http.StatusOK, http.StatusForbidden:
	default:
		panic(resp.Status)
	}

	if resp.Header.Get("X-Rehash") != "0" {
		panic("invalid X-Rehash header")
	}

	return resp.StatusCode == http.StatusOK
}

func main() {
	addr := flag.String("addr", "http://127.0.0.1:8080", "")
	count := flag.Int("count", 2, "")
	flag.Parse()

	uri, err := url.Parse(*addr)
	must(err)

	hashURL := *uri
	hashURL.Path = "/hash"

	verifyURL := *uri
	verifyURL.Path = "/verify"

	time.Sleep(2 * time.Second)

	hash := getHash(&hashURL, "password🔐🔓", "🔑", "📋")

	if !verify(&verifyURL, hash, "password🔐🔓", "🔑", "📋") {
		panic("failed")
	}

	must(quick.Check(func(password string) bool {
		return !verify(&verifyURL, hash, password, "🔑", "📋")
	}, &quick.Config{
		MaxCount: *count,
	}))

	must(quick.Check(func(key string) bool {
		return !verify(&verifyURL, hash, "password🔐🔓", key, "📋")
	}, &quick.Config{
		MaxCount: *count,

		Values: func(values []reflect.Value, rand *rand.Rand) {
			key, ok := quick.Value(reflect.TypeOf(""), rand)
			if !ok {
				panic("quick.Value failed")
			}

			if key.Len() > 32 {
				key = key.Slice(0, 32)
			}

			values[0] = key
		},
	}))

	must(quick.Check(func(ad string) bool {
		return !verify(&verifyURL, hash, "password🔐🔓", "🔑", ad)
	}, &quick.Config{
		MaxCount: *count,
	}))

	must(quick.Check(func(password, key, ad string) bool {
		hash := getHash(&hashURL, password, key, ad)
		return verify(&verifyURL, hash, password, key, ad)
	}, &quick.Config{
		MaxCount: *count,

		Values: func(values []reflect.Value, rand *rand.Rand) {
			for i := range values {
				var ok bool
				values[i], ok = quick.Value(reflect.TypeOf(""), rand)
				if !ok {
					panic("quick.Value failed")
				}
			}

			if values[1].Len() > 32 {
				values[1] = values[1].Slice(0, 32)
			}
		},
	}))
}
