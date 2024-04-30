package circuit

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestEncryptMimc(t *testing.T) {
	// Initialize a key and a message
	var key fr.Element
	var message fr.Element
	// For simplicity, we'll just fill the key and the message with some known values
	key.SetUint64(1)

	message.SetUint64(1)
	// Encrypt the message using EncryptMimc
	encrypted := EncryptMimcFr(key, message)

	// Print the message
	fmt.Printf("message: %v\n", message.ToBigIntRegular(new(big.Int)))

	// Print the encrypted message
	fmt.Printf("encrypted: %v\n", encrypted.ToBigIntRegular(new(big.Int)))

	// Print the key
	fmt.Printf("key: %v\n", key.ToBigIntRegular(new(big.Int)))
}
