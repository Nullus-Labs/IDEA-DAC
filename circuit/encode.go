package circuit

import (
	"fmt"
	"reflect"

	"github.com/consensys/gnark/frontend"
)

type Integer struct {
	X        frontend.Variable
	MaxDigit int
}

type String []frontend.Variable // Each var is a UTF-8 ASCII character

type Array []IsEmptyInterface // Each element is a Integer or String

type IsEmptyInterface interface {
	IsEmpty(api frontend.API) frontend.Variable
}

// Each var is a UTF-8 ASCII character
type Dict struct {
	keys   []String
	values []interface{}
}

func (x Integer) IsEmpty(api frontend.API) frontend.Variable {
	return api.IsZero(x.X)
}

func (x String) IsEmpty(api frontend.API) frontend.Variable {
	return isEqual(api, x[0], 0)
}

func (x Publication) IsEmpty(api frontend.API) frontend.Variable {
	return x.Title.IsEmpty(api)
}

func (x CovidTest) IsEmpty(api frontend.API) frontend.Variable {
	return x.Result.IsEmpty(api)
}

// Decimal Representation
func encodeNumber(api frontend.API, x Integer, mergeList [][]frontend.Variable) [][]frontend.Variable {
	// x = 101
	// xx[3] = [1, 0, 1]  // Hint
	// 1 * 100 + 0 * 10 + 1 * 1 = 101
	// yy[3] = [34, 33, 34] // Json
	decimal, err := api.Compiler().NewHint(getDecimal, x.MaxDigit+1, []frontend.Variable{x.MaxDigit, x.X}...)
	if err != nil {
		panic(err)
	}

	// RangeProof 0-9
	allValid := frontend.Variable(0)
	for i := 0; i < x.MaxDigit; i++ {
		valid := api.Add(withinBinary(api, decimal[i+1], 3), isEqual(api, decimal[i+1], 8), isEqual(api, decimal[i+1], 9))
		allValid = api.Add(allValid, valid)
	}
	api.AssertIsEqual(allValid, x.MaxDigit)
	// Check the decimal representation is correct
	total := frontend.Variable(0)
	remLen := decimal[0]
	isEnd := make([]frontend.Variable, x.MaxDigit)
	for i := 0; i < x.MaxDigit; i++ {
		isEnd[i] = api.IsZero(remLen)
		total = api.Select(isEnd[i], total, api.Mul(total, 10))
		api.AssertIsEqual(api.And(isEnd[i], boolNeg(api, api.IsZero(decimal[i+1]))), 0)
		total = api.Add(total, decimal[i+1])
		remLen = api.Select(isEnd[i], remLen, api.Sub(remLen, 1))
	}
	api.AssertIsEqual(total, x.X)
	res := make([]frontend.Variable, len(decimal))
	res[0] = decimal[0]
	for i := 1; i < len(decimal); i++ {
		res[i] = api.Select(isEnd[i-1], DUMMY, api.Add(decimal[i], 48))
	}
	mergeList = append(mergeList, res)
	return mergeList
}

// a-z A-Z ASCII
func encodeString(api frontend.API, str String, mergeList [][]frontend.Variable) [][]frontend.Variable {
	rangeCheckString(api, str)
	legitimateCheck(api, str)
	mergeList = append(mergeList, []frontend.Variable{1, int('"')})
	mergeList = append(mergeList, str)
	mergeList = append(mergeList, []frontend.Variable{1, int('"')})
	return mergeList
}

func encodeInterface(api frontend.API, in interface{}, mergeList [][]frontend.Variable) [][]frontend.Variable {
	if v, ok := in.(Integer); ok {
		return encodeNumber(api, v, mergeList)
	} else if v, ok := in.(String); ok {
		return encodeString(api, v, mergeList)
	} else if v, ok := in.(Array); ok {
		return encodeArray(api, v, mergeList)
	} else {
		v := reflect.ValueOf(in)
		t := v.Type()
		if t.Kind() == reflect.Slice {
			return encodeArray(api, toArray(api, in), mergeList)
		} else if t.Kind() == reflect.Struct {
			return encodeDict(api, toDict(api, in, MaxKeyLen), mergeList)
		} else {
			panic(fmt.Sprintf("Invalid type %v", t.Kind()))
		}
	}
}

func encodeArray(api frontend.API, arr Array, mergeList [][]frontend.Variable) [][]frontend.Variable {
	mergeList = append(mergeList, []frontend.Variable{1, int('[')})
	for i := 0; i < len(arr); i++ {
		var newMergeList [][]frontend.Variable
		if i != 0 {
			newMergeList = append(newMergeList, []frontend.Variable{1, int(',')})
		}
		isEmpty := arr[i].IsEmpty(api)
		newMergeList = encodeInterface(api, arr[i], newMergeList)
		for j := 0; j < len(newMergeList); j++ {
			newMergeList[j][0] = api.Select(isEmpty, 0, newMergeList[j][0])
			for k := 1; k < len(newMergeList[j]); k++ {
				newMergeList[j][k] = api.Select(isEmpty, DUMMY, newMergeList[j][k])
			}
		}
		mergeList = append(mergeList, newMergeList...)
	}
	mergeList = append(mergeList, []frontend.Variable{1, int(']')})
	return mergeList
}

// Ordered Dict by key
func encodeDict(api frontend.API, dict Dict, mergeList [][]frontend.Variable) [][]frontend.Variable {
	if len(dict.keys) != len(dict.values) {
		panic("Invalid Dict")
	}
	mergeList = append(mergeList, []frontend.Variable{1, int('{')})
	for i := 0; i < len(dict.keys); i++ {
		if i != 0 {
			mergeList = append(mergeList, []frontend.Variable{1, int(',')})
		}
		mergeList = encodeString(api, dict.keys[i], mergeList)
		mergeList = append(mergeList, []frontend.Variable{1, int(':')})
		mergeList = encodeInterface(api, dict.values[i], mergeList)
	}
	mergeList = append(mergeList, []frontend.Variable{1, int('}')})
	return mergeList
}

func toDict(api frontend.API, s interface{}, keyCapacity int) Dict {
	v := reflect.ValueOf(s)
	t := v.Type()
	if t.Kind() != reflect.Struct {
		// fmt.Println(t.Kind())
		panic("Invalid Type")
	}
	dict := Dict{}
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		dict.keys = append(dict.keys, toString(api, t.Field(i).Name, keyCapacity))
		dict.values = append(dict.values, field.Interface())
	}
	return dict
}

func toString(api frontend.API, s string, capacity int) String {
	if capacity < len(s) {
		panic("Invalid Capacity")
	}
	res := make(String, 0, capacity+1)
	res = append(res, len(s))
	for _, c := range s {
		res = append(res, int(c))
	}
	for i := len(s); i < capacity; i++ {
		res = append(res, DUMMY)
	}
	return res
}

func toArray(api frontend.API, s interface{}) Array {
	v := reflect.ValueOf(s)
	t := v.Type()
	if t.Kind() != reflect.Slice {
		panic("Invalid Type")
	}
	arr := Array{}
	for i := 0; i < v.Len(); i++ {
		arr = append(arr, v.Index(i).Interface().(IsEmptyInterface))
	}
	return arr
}
