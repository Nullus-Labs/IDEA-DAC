package circuit

import (
	"math/big"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

const DUMMY = 10000

// Merge Two length-ed array into one
func naiveMerge(api frontend.API, a, b []frontend.Variable) []frontend.Variable {
	l1 := a[0]
	l1Cpy := l1
	l2 := b[0]
	// l_out := api.Add(l1, l2)
	out := make([]frontend.Variable, len(a)+len(b)-1)
	out[0] = api.Add(l1, l2)
	// Avoid index overflow
	a_pad := make([]frontend.Variable, len(b)-1)
	for i := range a_pad {
		a_pad[i] = 0
	}
	a = append(a, a_pad...)
	// if l1 != 0, out[i] = a[i]
	// if l1 = 0 && l2 != 0, out[i] = b[i-l1]
	// if l1 = 0 && l2 = 0, out[i] = 0
	for i := 1; i < len(out); i++ {
		l1IsZero := api.IsZero(l1)
		l2IsZero := api.IsZero(l2)
		out[i] = api.Lookup2(l1IsZero, l2IsZero, a[i], multiplexer(api, b, api.Sub(i, l1Cpy)), a[i], 0)
		l1 = api.Select(l1IsZero, 0, api.Sub(l1, 1))
		l2 = api.Lookup2(l1IsZero, l2IsZero, l2, api.Sub(l2, 1), l2, 0)
	}
	return out
}

func merge(api frontend.API, a, b []frontend.Variable) []frontend.Variable {
	l1 := a[0]
	l2 := b[0]
	N1 := len(a) - 1
	N2 := len(b) - 1
	c, err := api.Compiler().NewHint(mergeHint, N1+N2+1, append([]frontend.Variable{N1, N2}, append(a, b...)...)...)
	if err != nil {
		panic(err)
	}
	// Check 1
	api.AssertIsEqual(c[0], api.Add(l1, l2))
	// Check 2
	rangeCheckString(api, c)
	// Check 3
	r := simpleHash(api, append(c, append(a, b...)...), 8)
	aMul := make([]frontend.Variable, N1)
	bMul := make([]frontend.Variable, N2)
	cMul := make([]frontend.Variable, N1+N2)
	for i := 0; i < N1; i++ {
		aMul[i] = api.Sub(r, api.Mul(api.Add(256*(i+1), a[i+1]), isNotDummy(api, a[i+1])))
	}
	for i := 0; i < N2; i++ {
		bMul[i] = api.Sub(r, api.Mul(api.Add(api.Mul(256, api.Add(l1, i+1)), b[i+1]), isNotDummy(api, b[i+1])))
	}
	for i := 0; i < N1+N2; i++ {
		cMul[i] = api.Sub(r, api.Mul(api.Add(256*(i+1), c[i+1]), isNotDummy(api, c[i+1])))
	}
	api.AssertIsEqual(api.Mul(batchMul(api, aMul), batchMul(api, bMul)), batchMul(api, cMul))
	return c
}

func batchMerge(api frontend.API, mergeList [][]frontend.Variable) []frontend.Variable {
	var hintInputs []frontend.Variable
	hintInputs = append(hintInputs, len(mergeList))
	maxLen := 0
	for i := range mergeList {
		maxLen += len(mergeList[i]) - 1
		hintInputs = append(hintInputs, len(mergeList[i]))
	}
	for i := range mergeList {
		hintInputs = append(hintInputs, mergeList[i]...)
	}
	c, err := api.Compiler().NewHint(batchMergeHint, maxLen+1, hintInputs...)
	if err != nil {
		panic(err)
	}
	// Check 1
	sum := frontend.Variable(0)
	for i := 0; i < len(mergeList); i++ {
		sum = api.Add(sum, mergeList[i][0])
	}
	api.AssertIsEqual(c[0], sum)
	// Check 2
	rangeCheckString(api, c)
	// Check 3
	r := simpleHash(api, append(hintInputs[len(mergeList)+1:], c...), 8)
	inputMul := make([]frontend.Variable, maxLen)
	curIdx := 0
	cumLen := frontend.Variable(0)
	for i := 0; i < len(mergeList); i++ {
		for j := 0; j < len(mergeList[i])-1; j++ {
			inputMul[curIdx] = api.Sub(r, api.Mul(api.Add(api.Mul(256, api.Add(cumLen, j+1)), mergeList[i][j+1]), isNotDummy(api, mergeList[i][j+1])))
			curIdx++
		}
		cumLen = api.Add(cumLen, mergeList[i][0])
	}
	cMul := make([]frontend.Variable, maxLen)
	for i := 0; i < maxLen; i++ {
		cMul[i] = api.Sub(r, api.Mul(api.Add(256*(i+1), c[i+1]), isNotDummy(api, c[i+1])))
	}
	api.AssertIsEqual(batchMul(api, inputMul), batchMul(api, cMul))
	return c
}

func batchMul(api frontend.API, a []frontend.Variable) frontend.Variable {
	length := len(a)
	if length == 1 {
		return a[0]
	}
	for len(a) > 1 {
		newLen := (len(a) + 1) / 2
		newArr := make([]frontend.Variable, newLen)
		for i := 0; i < newLen; i++ {
			if i*2+1 == len(a) {
				newArr[i] = a[i*2]
			} else {
				newArr[i] = api.Mul(a[i*2], a[i*2+1])
			}
		}
		a = newArr
	}
	return a[0]
}

func simpleHash(api frontend.API, items []frontend.Variable, itemBit int) frontend.Variable {
	items = mergeItems(api, items, itemBit)
	return mimcBinaryTree(api, items)
}

func mimcBinaryTree(api frontend.API, items []frontend.Variable) frontend.Variable {
	if len(items) == 1 {
		return items[0]
	}
	if len(items) == 2 {
		return mimcHash(api, items)
	}
	mid := (len(items) + 1) / 2
	return mimcHash(api, []frontend.Variable{mimcBinaryTree(api, items[:mid]), mimcBinaryTree(api, items[mid:])})
}

func mimcHash(api frontend.API, inputs []frontend.Variable) frontend.Variable {
	hash, _ := mimc.NewMiMC(api)
	hash.Write(inputs...)
	return hash.Sum()
}

func mergeItems(api frontend.API, items []frontend.Variable, itemBit int) []frontend.Variable {
	// each variable in items is itemBit bits
	rate := 253 / itemBit
	n := len(items) / rate
	if len(items)%rate != 0 {
		n++
	}
	newItem := make([]frontend.Variable, n)
	for i := 0; i < n; i++ {
		v := frontend.Variable(0)
		for j := 0; j < rate; j++ {
			k := i*rate + j
			if k >= len(items) {
				break
			}
			items[k] = api.Select(isDummy(api, items[k]), 0, items[k])
			v = api.Add(v, api.Mul(items[k], new(big.Int).Lsh(big.NewInt(1), uint(j*itemBit))))
		}

		newItem[i] = v
	}
	return newItem
}

func legitimateCheck(api frontend.API, a []frontend.Variable) {
	l := a[0]
	maxLen := len(a) - 1
	hasZero := frontend.Variable(0)
	reachEnd := frontend.Variable(0)
	allValid := frontend.Variable(0)
	c := make([]frontend.Variable, maxLen)
	for i := 0; i < maxLen; i++ {
		c[i] = frontend.Variable(0)
	}
	for i := 0; i < maxLen; i++ {
		isDummy := isDummy(api, a[i+1])
		reachEnd = api.Or(reachEnd, isDummy)
		c[i] = api.Select(isDummy, api.Sub(i+1, l), api.Sub(l, i+1))
		hasZero = api.Add(hasZero, api.IsZero(c[i]))
		if i > 0 {
			valid := api.Select(reachEnd, isEqual(api, c[i], api.Add(c[i-1], 1)), isEqual(api, c[i], api.Sub(c[i-1], 1)))
			allValid = api.Add(allValid, valid)
		}
	}
	api.AssertIsEqual(allValid, maxLen-1)
	// Either is true
	lIsZero := api.IsZero(l)
	api.AssertIsEqual(api.Or(hasZero, lIsZero), 1)
	api.AssertIsEqual(api.And(hasZero, lIsZero), 0)
}

func rangeCheckString(api frontend.API, a []frontend.Variable) {
	maxLen := len(a) - 1
	allValid := frontend.Variable(0)
	for i := 0; i < maxLen; i++ {
		valid := api.Add(withinBinary(api, a[i+1], 8), isDummy(api, a[i+1]))
		allValid = api.Add(allValid, valid)
	}
	api.AssertIsEqual(allValid, maxLen)
}

func multiplexer(api frontend.API, inputs []frontend.Variable, index frontend.Variable) frontend.Variable {
	logUpperBound := 0
	for n := len(inputs); n > 0; n >>= 1 {
		logUpperBound++
	}

	res := make([]frontend.Variable, 1<<logUpperBound)
	for i := 0; i < len(inputs); i++ {
		res[i] = inputs[i]
	}
	for i := len(inputs); i < len(res); i++ {
		res[i] = frontend.Variable(0)
	}

	// Avoid negative index
	_, index = iDivModBit(api, index, logUpperBound)

	indexBin := api.ToBinary(index, logUpperBound)
	for i := 0; i < len(indexBin); i++ {
		for j := 0; j < (1 << (logUpperBound - i - 1)); j++ {
			res[j] = api.Select(indexBin[i], res[2*j+1], res[2*j])
		}
	}
	return res[0]
}

func iDivModBit(api frontend.API, a frontend.Variable, b int) (frontend.Variable, frontend.Variable) {
	rets, err := api.Compiler().NewHint(idiv, 2, a, leftShift(1, uint64(b)))
	if err != nil {
		panic("i_div_mod error: " + err.Error())
		// return 0, 0
	} else {
		quotient := rets[0]
		remainder := rets[1]
		api.ToBinary(remainder, b)
		api.AssertIsEqual(api.Add(api.Mul(leftShift(1, uint64(b)), quotient), remainder), a)
		return quotient, remainder
	}
}

// leftShift returns (k << n)
func leftShift(k int64, n uint64) *big.Int {
	z := big.NewInt(k)
	return z.Lsh(z, uint(n))
}

func isEqual(api frontend.API, a frontend.Variable, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Sub(a, b))
}

func isGreater(api frontend.API, a frontend.Variable, b frontend.Variable) frontend.Variable {
	return isEqual(api, api.Cmp(a, b), 1)
}

func isLess(api frontend.API, a frontend.Variable, b frontend.Variable) frontend.Variable {
	return isEqual(api, api.Cmp(a, b), -1)
}

func isLessOrEqual(api frontend.API, a frontend.Variable, b frontend.Variable) frontend.Variable {
	return boolNeg(api, isGreater(api, a, b))
}

func boolNeg(api frontend.API, a frontend.Variable) frontend.Variable {
	return api.Sub(1, a)
}

func isDummy(api frontend.API, x frontend.Variable) frontend.Variable {
	return isEqual(api, x, DUMMY)
}

func isNotDummy(api frontend.API, x frontend.Variable) frontend.Variable {
	return api.Sub(1, isEqual(api, x, DUMMY))
}

func withinBinary(api frontend.API, v frontend.Variable, n int) frontend.Variable {
	c := big.NewInt(1)

	bits, err := api.Compiler().NewHint(NBits, n, v)
	if err != nil {
		panic(err)
	}

	var Σbi frontend.Variable
	Σbi = 0
	for i := 0; i < n; i++ {
		Σbi = api.Add(Σbi, api.Mul(bits[i], c))
		c.Lsh(c, 1)
		api.AssertIsBoolean(bits[i])
	}
	// return if Σ (2**i * b[i]) == a
	return isEqual(api, Σbi, v)
}

func CommitMiMC(msg []byte) []byte {
	if len(msg) > 32 {
		panic("Message Too Long")
	}
	inputs := make([]byte, 32-len(msg))
	for i := range inputs {
		inputs[i] = 0
	}
	inputs = append(inputs, msg...)
	mimc := bn254.NewMiMC()
	mimc.Write(inputs)
	sum := mimc.Sum([]byte{})
	return sum
}

func StringToAscii(input string) []int64 {
	var res []int64
	//res = append(res, int64(len(input)))
	for _, c := range input {
		res = append(res, int64(c))
	}
	return res
}
