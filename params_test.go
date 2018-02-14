package portunes

import (
	"testing"
	"testing/quick"

	"github.com/stretchr/testify/assert"
)

func TestParamEncoding(t *testing.T) {
	t.Parallel()

	assert.NoError(t, quick.Check(func(time, memory uint32, threads uint8) bool {
		buf := appendParams(nil, time, memory, threads)
		time2, memory2, threads2, _ := consumeParams(buf)
		return time == time2 && memory == memory2 && threads == threads2
	}, &quick.Config{
		MaxCountScale: 10000,
	}))
}
