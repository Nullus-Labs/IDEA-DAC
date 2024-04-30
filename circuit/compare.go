package circuit

import (
	"github.com/consensys/gnark/frontend"
)

func checkAppendOnlyPhd(api frontend.API, oldContent []Publication, newContent []Publication) frontend.Variable {
	if len(oldContent) != len(newContent) {
		panic("oldContent and newContent should have the same length")
	}
	preEqual := frontend.Variable(1)
	notEqual := frontend.Variable(0)
	postEqual := frontend.Variable(1)
	for i := 0; i < len(oldContent); i++ {
		checkNone := api.And(oldContent[i].IsEmpty(api), newContent[i].IsEmpty(api))
		postEqual = api.Select(notEqual, api.And(checkNone, postEqual), postEqual)
		preEqual = api.And(preEqual, isEqualInterface(api, oldContent[i].Title, newContent[i].Title))
		preEqual = api.And(preEqual, isEqualInterface(api, oldContent[i].Year, newContent[i].Year))
		notEqual = api.Select(preEqual, api.And(frontend.Variable(0), notEqual), frontend.Variable(1))
	}
	return postEqual
}

func checkAppendOnlyCovid(api frontend.API, oldContent []CovidTest, newContent []CovidTest) frontend.Variable {
	if len(oldContent) != len(newContent) {
		panic("oldContent and newContent should have the same length")
	}
	preEqual := frontend.Variable(1)
	notEqual := frontend.Variable(0)
	postEqual := frontend.Variable(1)
	for i := 0; i < len(oldContent); i++ {
		checkNone := api.And(oldContent[i].IsEmpty(api), newContent[i].IsEmpty(api))
		postEqual = api.Select(notEqual, api.And(checkNone, postEqual), postEqual)
		preEqual = api.And(preEqual, isEqualInterface(api, oldContent[i].TestDate, newContent[i].TestDate))
		preEqual = api.And(preEqual, isEqualInterface(api, oldContent[i].Result, newContent[i].Result))
		notEqual = api.Select(preEqual, api.And(frontend.Variable(0), notEqual), frontend.Variable(1))
	}
	return postEqual
}

func isEqualInterface(api frontend.API, a interface{}, b interface{}) frontend.Variable {
	if x, ok := a.(Integer); ok {
		if y, ok2 := b.(Integer); ok2 {
			return isEqualInteger(api, x, y)
		}
	} else if x, ok := a.(String); ok {
		if y, ok2 := b.(String); ok2 {
			return isEqualString(api, x, y)
		}
	} else if x, ok := a.(Array); ok {
		if y, ok2 := b.(Array); ok2 {
			return isEqualArray(api, x, y)
		}
	} else if x, ok := a.(Dict); ok {
		if y, ok2 := b.(Dict); ok2 {
			return isEqualDict(api, x, y)
		}
	} else {
		panic("Invalid Type")
	}
	return frontend.Variable(0)
}

func isEqualDict(api frontend.API, a Dict, b Dict) frontend.Variable {
	if len(a.keys) != len(b.keys) || len(a.values) != len(b.values) {
		return 0
	}
	judge := frontend.Variable(0)
	for i := 0; i < len(a.keys); i++ {
		judge = api.Add(judge, isEqualString(api, a.keys[i], b.keys[i]))
		judge = api.Add(judge, isEqualInterface(api, a.values[i], b.values[i]))
	}
	return isEqual(api, judge, len(a.keys)*2)
}

func isEqualArray(api frontend.API, a Array, b Array) frontend.Variable {
	if len(a) != len(b) {
		return 0
	}
	judge := frontend.Variable(0)
	for i := 0; i < len(a); i++ {
		judge = api.Add(judge, isEqualInterface(api, a[i], b[i]))
	}
	return isEqual(api, judge, len(a))
}

func isEqualString(api frontend.API, x String, y String) frontend.Variable {
	if len(x) != len(y) {
		return 0
	}
	judge := frontend.Variable(0)
	for i := 0; i < len(x); i++ {
		judge = api.Add(judge, isEqual(api, x[i], y[i]))
	}
	return isEqual(api, judge, len(x))
}

func isEqualInteger(api frontend.API, a Integer, b Integer) frontend.Variable {
	return isEqual(api, a.X, b.X)
}

func checkWithinRange(api frontend.API, lower frontend.Variable, upper frontend.Variable, value frontend.Variable) frontend.Variable {
	return api.And(isLessOrEqual(api, value, upper), isLessOrEqual(api, lower, value))
}

// todo: deal with dummy, in reality, n may be variable-length
func checkOneOfSet(api frontend.API, n int, set []String, value String) frontend.Variable {
	judge := frontend.Variable(0)
	for i := 0; i < n; i++ {
		judge = api.Add(judge, isEqualInterface(api, set[i], value))
	}
	return judge
}

func checkTimeInRange(api frontend.API, timeRange frontend.Variable, initTime frontend.Variable, targetTime frontend.Variable) frontend.Variable {
	//target time is within the time range of init time and target time is smaller than init time
	return api.And(isLess(api, initTime, targetTime), isLess(api, api.Add(initTime, timeRange), targetTime))
}

func checkFormat(api frontend.API, n int, format []frontend.Variable, value String) frontend.Variable {
	// Predefine: 1: Capital Letter, 2: Small Letter, 3: Number, 4: Special Character
	// n is the length of the format
	judge := frontend.Variable(1)
	//Skip first position
	for i := 1; i < n+1; i++ {
		check1 := api.Select(isEqual(api, format[i-1], 1), api.And(isLess(api, api.Sub(value[i], 65), 26), isGreater(api, api.Sub(value[i], 65), 0)), 0)
		check2 := api.Select(isEqual(api, format[i-1], 2), api.And(isLess(api, api.Sub(value[i], 97), 26), isGreater(api, api.Sub(value[i], 97), 0)), 0)
		check3 := api.Select(isEqual(api, format[i-1], 3), api.And(isLess(api, api.Sub(value[i], 48), 10), isGreater(api, api.Sub(value[i], 48), 0)), 0)
		check4 := api.Select(isEqual(api, format[i-1], 4), api.And(isLess(api, api.Sub(value[i], 33), 15), isGreater(api, api.Sub(value[i], 33), 0)), 0)
		judge = api.And(judge, api.Or(api.Or(check1, check2), api.Or(check3, check4)))
	}
	return judge
}
