package portunes

type params struct {
	Passes uint32 // time
	Lanes  uint8  // threads
	Memory uint32

	SaltLen int
	HashLen int // keyLen

	Rehash bool
}

var paramsList = []params{
	params{
		Passes: 3,
		Lanes:  2,
		Memory: 1 << 19,

		SaltLen: 16,
		HashLen: 16,
	},
}

var paramsCurIdx = len(paramsList) - 1

func init() {
	if paramsList[paramsCurIdx].Rehash {
		panic("paramsList[paramsCurIdx].Rehash is true")
	}
}
