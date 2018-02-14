package portunes

import (
	"encoding/binary"
	"math/bits"
)

func appendVarint32(buf []byte, v uint32) []byte {
	var tmp [binary.MaxVarintLen32]byte
	n := binary.PutUvarint(tmp[:], uint64(v))
	return append(buf, tmp[:n]...)
}

func consumeVarint32(buf []byte) (uint32, []byte, bool) {
	tmp, n := binary.Uvarint(buf)
	if n <= 0 || tmp>>32 != 0 {
		return 0, nil, false
	}

	return uint32(tmp), buf[n:], true
}

const maxParamsLength = 2 + 2*binary.MaxVarintLen32

const paramsV0 = 0

func appendParams(buf []byte, time, memory uint32, threads uint8) []byte {
	buf = appendVarint32(buf,
		uint32(threads-1)<<(paramsV0+1)|
			((1<<paramsV0)-1))
	buf = appendVarint32(buf, time-1)
	return appendVarint32(buf,
		bits.RotateLeft32(memory, -16))
}

func consumeParams(buf []byte) (time, memory uint32, threads uint8, rest []byte) {
	tmp, buf, ok0 := consumeVarint32(buf)

	vers := bits.TrailingZeros32(^tmp)
	if vers != paramsV0 || !ok0 {
		return 0, 0, 0, nil
	}

	time, buf, ok1 := consumeVarint32(buf)
	memory, buf, ok2 := consumeVarint32(buf)

	if !ok1 || !ok2 || tmp>>(8+paramsV0+1) != 0 {
		return 0, 0, 0, nil
	}

	time++
	memory = bits.RotateLeft32(memory, 16)
	threads = uint8(tmp>>(paramsV0+1)) + 1

	return time, memory, threads, buf
}
