package circuit

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type EncryptMIMCCircuit struct {
	Key        frontend.Variable
	Content    frontend.Variable
	EncContent frontend.Variable `gnark:",public"`
}


func (circuit *EncryptMIMCCircuit) Define(api frontend.API) error {
	EncData := encryptMimc(api, circuit.Key, circuit.Content)
	api.AssertIsEqual(circuit.EncContent, EncData)
	return nil
}

func Test_EncryptMIMCCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit EncryptMIMCCircuit

	key := new(fr.Element).SetInt64(1111)
	message := new(fr.Element).SetInt64(2222)
	enc := EncryptMimcFr(*key, *message)

	assert.ProverSucceeded(&circuit, &EncryptMIMCCircuit{
		Key:        key,
		Content:    message,
		EncContent: enc,
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}
