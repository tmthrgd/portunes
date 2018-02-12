package portunes

type params struct {
	Passes uint32 // time
	Lanes  uint8  // threads
	Memory uint32

	SaltLen int
	HashLen int // keyLen

	Rehash bool

	Version uint32
}

var params0 = &params{
	Passes: 3,
	Lanes:  2,
	Memory: 1 << 19,

	SaltLen: 16,
	HashLen: 16,
}

var paramsMap = map[uint32]*params{
	0: params0,
}

var paramsCur = params0

func init() {
	if paramsCur.Rehash {
		panic("paramsCur.Rehash is true")
	}

	for vers, params := range paramsMap {
		if params.Version != vers {
			panic("paramsMap has mismatched version")
		}
	}
}
