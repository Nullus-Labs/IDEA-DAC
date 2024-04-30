package circuit

import (
	"errors"
	"math/big"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

const MergeLen = 31

var encryptFuncs map[ecc.ID]func(MiMC, frontend.Variable) frontend.Variable
var newMimc map[ecc.ID]func(frontend.API) MiMC

// MiMC contains the params of the Mimc hash func and the curves on which it is implemented
type MiMC struct {
	params []big.Int           // c_i
	id     ecc.ID              // id needed to know which encryption function to use
	k      frontend.Variable   // key
	data   []frontend.Variable // state storage. data is updated when Write() is called. Sum sums the data.
	api    frontend.API        // underlying constraint system
}

// NewMiMC returns a MiMC instance, than can be used in a gnark circuit
func NewMiMC(api frontend.API) (MiMC, error) {
	if constructor, ok := newMimc[ecc.BN254]; ok {
		return constructor(api), nil
	}
	return MiMC{}, errors.New("unknown curve id")
}

// Write adds more data to the running hash.
func (h *MiMC) Write(data ...frontend.Variable) {
	h.data = append(h.data, data...)
}

// Reset resets the Hash to its initial state.
func (h *MiMC) Reset() {
	h.data = nil
	h.k = 0
}

// Hash hash (in r1cs form) using Miyaguchi–Preneel:
// https://en.wikipedia.org/wiki/One-way_compression_function
// The XOR operation is replaced by field addition.
// See github.com/consensys/gnark-crypto for reference implementation.
func (h *MiMC) Sum() frontend.Variable {

	//h.Write(data...)s
	for _, stream := range h.data {
		r := encryptFuncs[h.id](*h, stream)
		h.k = h.api.Add(h.k, r, stream)
	}

	h.data = nil // flush the data already hashed

	return h.k

}

func pow5(api frontend.API, x frontend.Variable) frontend.Variable {
	r := api.Mul(x, x)
	r = api.Mul(r, r)
	return api.Mul(r, x)
}

// m is the message, k the key
func encryptPow5(h MiMC, m frontend.Variable) frontend.Variable {
	x := m
	for i := 0; i < len(h.params); i++ {
		x = pow5(h.api, h.api.Add(x, h.k, h.params[i]))
	}
	return h.api.Add(x, h.k)
}

func newMimcBN254(api frontend.API) MiMC {
	res := MiMC{}
	res.params = bn254.GetConstants()
	res.id = ecc.BN254
	res.k = 0
	res.api = api
	return res
}

func encryptMimc(api frontend.API, key frontend.Variable, message frontend.Variable) frontend.Variable {
	// create Mimc function with the api
	F, _ := NewMiMC(api)
	// set the fields
	F.params = bn254.GetConstants()
	F.id = ecc.BN254
	F.k = key
	F.api = api
	// encrypt the message using CBC mode
	// Define an initialization vector (IV). This can be a predefined constant or a random value.
	// We'll use a predefined constant for this example.
	return encryptPow5(F, message)
}

// Message[0] is the length of the whole message
func encrypt(api frontend.API, key frontend.Variable, message []frontend.Variable) []frontend.Variable {
	merged, isDummy := compress(api, message)
	res := make([]frontend.Variable, len(merged))
	for i := 0; i < len(merged); i++ {
		//api.Println(merged[i])
		res[i] = api.Select(isDummy[i], 0, encryptMimc(api, key, merged[i]))
		//api.Println(res[i])
	}
	return res
}

// Little Endian
func compress(api frontend.API, msg []frontend.Variable) ([]frontend.Variable, []frontend.Variable) {
	var res []frontend.Variable
	var isDummy []frontend.Variable
	for i := 1; i < len(msg); i += MergeLen {
		thisItem := frontend.Variable(0)
		totalNotDummy := frontend.Variable(0)
		// 2^{8j} * m[j] * IsNotDummy(m[j])
		for j := 0; j < MergeLen; j++ {
			if i+j >= len(msg) {
				break
			}
			notDummy := isNotDummy(api, msg[i+j])
			totalNotDummy = api.Add(totalNotDummy, notDummy)
			thisItem = api.Add(thisItem, api.Mul(leftShift(1, uint64(8*j)), msg[i+j], notDummy))
		}
		res = append(res, thisItem)
		isDummy = append(isDummy, api.IsZero(totalNotDummy))
	}
	return res, isDummy
}
