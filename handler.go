package portunes

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"io/ioutil"
	"net/http"
	_ "unsafe" // for go:linkname

	_ "golang.org/x/crypto/argon2" // for argon2_deriveKey
)

//go:linkname argon2_deriveKey golang.org/x/crypto/argon2.deriveKey
func argon2_deriveKey(mode int, password, salt, secret, data []byte, time, memory uint32, threads uint8, keyLen uint32) []byte

const (
	HashPath   = "/hash"
	VerifyPath = "/verify"
)

const (
	HashMethod   = http.MethodPost
	VerifyMethod = http.MethodPost
)

const maxBody = 16 << 25 // 16MiB

var (
	methodNotAllowedText = http.StatusText(http.StatusMethodNotAllowed)
	badRequestText       = http.StatusText(http.StatusBadRequest)
)

func methodCheck(w http.ResponseWriter, r *http.Request, expect string) bool {
	if r.Method == expect {
		return true
	}

	w.Header().Set("Allow", expect)
	http.Error(w, methodNotAllowedText, http.StatusMethodNotAllowed)
	return false
}

func errCheck(w http.ResponseWriter, err error) bool {
	if err == nil {
		return true
	}

	http.Error(w, err.Error(), http.StatusInternalServerError)
	return false
}

func Hash(w http.ResponseWriter, r *http.Request) {
	if !methodCheck(w, r, HashMethod) {
		return
	}

	body := http.MaxBytesReader(w, r.Body, maxBody)
	defer body.Close()

	salt := make([]byte, paramsCur.SaltLen)
	if _, err := rand.Read(salt); !errCheck(w, err) {
		return
	}

	ad := []byte(r.Header.Get("X-Associated-Data"))
	key := []byte(r.Header.Get("X-Key"))

	data, err := ioutil.ReadAll(body)
	if !errCheck(w, err) {
		return
	}

	hash := argon2_deriveKey(int(paramsCur.Variant),
		data, salt, key, ad,
		paramsCur.Passes, paramsCur.Memory,
		paramsCur.Lanes, uint32(paramsCur.HashLen))

	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], paramsCur.Version)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)

	w.Write(hdr[:])
	w.Write(salt)
	w.Write(hash)
}

func Verify(w http.ResponseWriter, r *http.Request) {
	if !methodCheck(w, r, VerifyMethod) {
		return
	}

	body := http.MaxBytesReader(w, r.Body, maxBody)
	defer body.Close()

	var version uint16
	if err := binary.Read(body, binary.BigEndian, &version); !errCheck(w, err) {
		return
	}

	params, ok := paramsMap[version]
	if !ok {
		http.Error(w, badRequestText, http.StatusBadRequest)
		return
	}

	salt := make([]byte, params.SaltLen)
	if _, err := io.ReadFull(body, salt); !errCheck(w, err) {
		return
	}

	hash := make([]byte, params.HashLen)
	if _, err := io.ReadFull(body, hash); !errCheck(w, err) {
		return
	}

	data, err := ioutil.ReadAll(body)
	if !errCheck(w, err) {
		return
	}

	ad := []byte(r.Header.Get("X-Associated-Data"))
	key := []byte(r.Header.Get("X-Key"))

	expect := argon2_deriveKey(int(params.Variant),
		data, salt, key, ad,
		params.Passes, params.Memory,
		params.Lanes, uint32(params.HashLen))

	w.Header().Set("X-Rehash", formatBool(params.Rehash))

	if subtle.ConstantTimeCompare(expect, hash) == 1 {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusForbidden)
	}
}

func formatBool(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
