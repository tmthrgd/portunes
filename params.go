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
	if n <= 0 || tmp&^(1<<32-1) != 0 {
		return 0, nil, false
	}

	return uint32(tmp), buf[n:], true
}

const maxParamsLength = 2 + 2*binary.MaxVarintLen32

func appendParams(buf []byte, time, memory uint32, threads uint8) []byte {
	time, threads = time-1, threads-1

	if threads <= 0x1f && time <= 0x03 {
		buf = append(buf, uint8(time<<5)|threads)
	} else {
		if threads < 0x7f {
			buf = append(buf, 0x80|threads)
		} else {
			buf = append(buf, 0x80|0x7f, threads-0x7f)
		}

		buf = appendVarint32(buf, time)
	}

	memory = bits.RotateLeft32(memory, -16)
	return appendVarint32(buf, memory)
}

func consumeParams(buf []byte) (time, memory uint32, threads uint8, rest []byte) {
	failed := func() (uint32, uint32, uint8, []byte) {
		return 0, 0, 0, nil
	}

	if len(buf) < 1 {
		return failed()
	}

	if buf[0]&0x80 == 0 {
		threads = buf[0] & 0x1f
		time = uint32(buf[0]) >> 5
		buf = buf[1:]
	} else {
		if buf[0] == 0xff {
			if len(buf) < 2 {
				return failed()
			}

			threads = buf[1] + 0x7f
			buf = buf[2:]
		} else {
			threads = buf[0] & 0x7f
			buf = buf[1:]
		}

		var ok bool
		time, buf, ok = consumeVarint32(buf)
		if !ok {
			return failed()
		}
	}

	memory, buf, ok := consumeVarint32(buf)
	if !ok {
		return failed()
	}

	time, threads = time+1, threads+1
	memory = bits.RotateLeft32(memory, 16)

	return time, memory, threads, buf
}
