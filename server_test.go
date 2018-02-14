package portunes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/argon2"
)

func TestArgon2Version(t *testing.T) {
	assert.Equal(t, 0x13, argon2.Version)
}
