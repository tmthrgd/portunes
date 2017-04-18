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

	req, err := http.NewRequest(http.MethodPost, hashURL.String(), strings.NewReader("password🔐🔓"))
	must(err)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Key", "🔑")
	req.Header.Set("X-Associated-Data", "📋")

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
			v, ok := quick.Value(reflect.TypeOf(""), rand)
			if !ok {
				panic("quick.Value failed")
			}

			if v.Len() > 32 {
				v = v.Slice(0, 32)
			}

			values[0] = v
		},
	}))

	must(quick.Check(func(ad string) bool {
		return !verify(&verifyURL, hash, "password🔐🔓", "🔑", ad)
	}, &quick.Config{
		MaxCount: *count,
	}))
}
