package portunes

type variant int

const (
	argon2d variant = iota
	argon2i
	argon2id
)

type params struct {
	Passes  uint32 // time
	Lanes   uint8  // threads
	Memory  uint32
	Variant variant

	SaltLen int
	HashLen int // keyLen

	Rehash bool

	Version uint32
}

var (
	params0 = &params{
		Passes:  3,
		Lanes:   2,
		Memory:  1 << 19,
		Variant: argon2id,

		SaltLen: 16,
		HashLen: 16,
	}
)

var paramsMap = map[uint32]*params{
	0: params0,
}

var paramsCur = params0

func init() {
	for vers, params := range paramsMap {
		if params.Version != vers {
			panic("paramsMap not 1:1")
		}
	}
}
