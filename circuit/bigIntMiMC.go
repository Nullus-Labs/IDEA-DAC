package circuit

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"golang.org/x/crypto/sha3"
	"math/big"
	"sync"
)

const (
	mimcNbRounds = 91
	seed         = "seed"   // seed to derive the constants
	BlockSize    = fr.Bytes // BlockSize size that mimc consumes
)

// Params constants for the mimc hash function
var (
	mimcConstants [mimcNbRounds]fr.Element
	once          sync.Once
)

// digest represents the partial evaluation of the checksum
// along with the params of the mimc function
type digest struct {
	h      fr.Element
	params []big.Int
	data   []byte // data to hash
}

func (d *digest) Reset() {
	d.data = nil
	d.h = fr.Element{0, 0, 0, 0}
}

// Hash hash using Miyaguchi–Preneel:
// https://en.wikipedia.org/wiki/One-way_compression_function
// The XOR operation is replaced by field addition, data is in Montgomery form
func (d *digest) checksum() fr.Element {

	var buffer [BlockSize]byte
	var x fr.Element

	// if data size is not multiple of BlockSizes we padd:
	// .. || 0xaf8 -> .. || 0x0000...0af8
	if len(d.data)%BlockSize != 0 {
		q := len(d.data) / BlockSize
		r := len(d.data) % BlockSize
		sliceq := make([]byte, q*BlockSize)
		copy(sliceq, d.data)
		slicer := make([]byte, r)
		copy(slicer, d.data[q*BlockSize:])
		sliceremainder := make([]byte, BlockSize-r)
		d.data = append(sliceq, sliceremainder...)
		d.data = append(d.data, slicer...)
	}

	if len(d.data) == 0 {
		d.data = make([]byte, 32)
	}

	nbChunks := len(d.data) / BlockSize

	for i := 0; i < nbChunks; i++ {
		copy(buffer[:], d.data[i*BlockSize:(i+1)*BlockSize])
		x.SetBytes(buffer[:])
		r := d.encrypt(x)
		d.h.Add(&r, &d.h).Add(&d.h, &x)
	}

	return d.h
}

// plain execution of a mimc run
// m: message
// k: encryption key
func (d *digest) encrypt(m fr.Element) fr.Element {
	once.Do(initConstants) // init constants
	params := bn254.GetConstants()
	//for i := 0; i < mimcNbRounds; i++ {
	for i := 0; i < len(params); i++ {
		// m = (m+k+c)^5
		var tmp fr.Element
		var param fr.Element
		tmp.Add(&m, &d.h).Add(&tmp, param.SetBigInt(&params[i]))
		m.Square(&tmp).
			Square(&m).
			Mul(&m, &tmp)
	}
	m.Add(&m, &d.h)
	return m
}

func initConstants() {
	bseed := ([]byte)(seed)

	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write(bseed)
	rnd := hash.Sum(nil) // pre hash before use
	hash.Reset()
	_, _ = hash.Write(rnd)

	for i := 0; i < mimcNbRounds; i++ {
		rnd = hash.Sum(nil)
		mimcConstants[i].SetBytes(rnd)
		hash.Reset()
		_, _ = hash.Write(rnd)
	}
}

func EncryptMimcFr(key fr.Element, message fr.Element) fr.Element {
	// create a new digest
	var d digest
	d.Reset()
	d.h = key
	return d.encrypt(message)
}
