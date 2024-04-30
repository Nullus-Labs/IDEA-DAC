package circuit

import (
	"github.com/consensys/gnark/backend/hint"
	"math/big"
)

func init() {
	hint.Register(idiv)
	hint.Register(getDecimal)
	hint.Register(NBits)
	hint.Register(mergeHint)
	hint.Register(batchMergeHint)
}
func getDecimal(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	maxDigit := inputs[0].Int64()
	x := inputs[1].String()
	if len(x) > int(maxDigit) {
		panic("input is too large")
	}
	for i := 0; i < len(x); i++ {
		outputs[i+1].SetInt64(int64(x[i]) - 48)
	}
	outputs[0].SetInt64(int64(len(x)))
	return nil
}

func idiv(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	zero := big.NewInt(0)
	if inputs[0].Cmp(zero) == 0 && inputs[1].Cmp(zero) == 0 {
		outputs[0] = big.NewInt(1)
		outputs[1] = big.NewInt(0)
		return nil
	} else if inputs[1].Cmp(zero) == 0 {
		outputs[0] = big.NewInt(0)
		outputs[1] = inputs[0]
		return nil
		// return errors.New("idiv: Divide by Zero")
	}
	outputs[0].DivMod(inputs[0], inputs[1], outputs[1])
	outputs[0].Mod(outputs[0], field)
	outputs[1].Mod(outputs[1], field)
	return nil
}

// NBits returns the first bits of the input. The number of returned bits is
// defined by the length of the results slice.
func NBits(field *big.Int, inputs []*big.Int, results []*big.Int) error {
	n := inputs[0]
	for i := 0; i < len(results); i++ {
		results[i].SetUint64(uint64(n.Bit(i)))
	}
	return nil
}

func mergeHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	N1 := inputs[0].Uint64()
	N2 := inputs[1].Uint64()
	aLen := inputs[2].Uint64()
	a := inputs[3 : 3+N1]
	//fmt.Println("total:", len(a))
	//fmt.Println(aLen)
	bLen := inputs[3+N1].Uint64()
	b := inputs[4+N1 : 4+N1+N2]
	outputs[0] = new(big.Int).SetUint64(aLen + bLen)
	for i := uint64(0); i < aLen; i++ {
		outputs[i+1] = new(big.Int).Set(a[i])
	}
	for i := uint64(0); i < bLen; i++ {
		outputs[i+1+aLen] = new(big.Int).Set(b[i])
	}
	for i := aLen + bLen + 1; i < N1+N2+1; i++ {
		outputs[i] = new(big.Int).SetUint64(DUMMY)
	}
	return nil
}

func batchMergeHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	num := inputs[0].Uint64()
	var mergeLen []uint64
	for i := uint64(0); i < num; i++ {
		mergeLen = append(mergeLen, inputs[1+i].Uint64())
	}
	curInIdx := 1 + num
	curOutIdx := uint64(0)
	for i := uint64(0); i < num; i++ {
		thisString := inputs[curInIdx : curInIdx+mergeLen[i]]
		thisLen := thisString[0].Uint64()
		copy(outputs[curOutIdx+1:curOutIdx+1+thisLen], thisString[1:1+thisLen])
		curOutIdx += thisLen
		curInIdx += mergeLen[i]
	}
	outputs[0].SetUint64(curOutIdx)
	for i := int(curOutIdx) + 1; i < len(outputs); i++ {
		outputs[i].SetUint64(DUMMY)
	}
	return nil
}
