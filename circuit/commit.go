package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

func commit(api frontend.API, msg frontend.Variable) frontend.Variable {
	hash, _ := mimc.NewMiMC(api)
	hash.Write(msg)
	return hash.Sum()
}
