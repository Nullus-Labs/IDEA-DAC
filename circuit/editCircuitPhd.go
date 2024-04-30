package circuit

import (
	"github.com/consensys/gnark/frontend"
)

func EditCheckPhd(api frontend.API, OldRecord []frontend.Variable, NewRecord []frontend.Variable, limit PhdLimit, commitedKey frontend.Variable, oldContent PhDProfile, newContent PhDProfile, Key frontend.Variable) {
	contentCheckPhd(api, commitedKey, Key, oldContent, newContent, OldRecord, NewRecord, limit)
}

func contentCheckPhd(api frontend.API, commitedKey frontend.Variable, Key frontend.Variable, oldContent PhDProfile, newContent PhDProfile, oldRecord []frontend.Variable, newRecord []frontend.Variable, limit PhdLimit) {
	compareContentPhd(api, oldContent, newContent, limit)
	api.AssertIsEqual(commitedKey, commit(api, Key))

	encodedOldContent := encodePhdProfile(api, oldContent)
	assertArrayEqualWithUnequalLength(api, oldRecord, encrypt(api, Key, encodedOldContent))

	encodedNewContent := encodePhdProfile(api, newContent)
	assertArrayEqualWithUnequalLength(api, newRecord, encrypt(api, Key, encodedNewContent))
}

func compareContentPhd(api frontend.API, oldContent PhDProfile, newContent PhDProfile, limit PhdLimit) {
	sum := frontend.Variable(0)
	sum = api.Add(sum, checkAppendOnlyPhd(api, oldContent.Publications[:], newContent.Publications[:]))
	sum = api.Add(sum, checkOneOfSet(api, 4, limit.StatusSet[:], newContent.Status))
	sum = api.Add(sum, checkWithinRange(api, limit.YearRange[0], limit.YearRange[1], newContent.ProgramYear.X))
	sum = api.Add(sum, checkTimeInRange(api, api.Mul(limit.TimeMinRange.X, OneYearUnix), newContent.Duration.Start.X, newContent.Duration.End.X))
	sum = api.Add(sum, checkFormat(api, 5, limit.Format, newContent.StudentID))
	sum = api.Add(sum, isEqualString(api, oldContent.StudentID, newContent.StudentID))
	api.AssertIsEqual(sum, frontend.Variable(6))
}

func encodePhdProfile(api frontend.API, profile PhDProfile) []frontend.Variable {
	var mergeList [][]frontend.Variable
	mergeList = encodeDict(api, toDict(api, profile, MaxKeyLen), mergeList)
	return batchMerge(api, mergeList)
}

func assertArrayEqualWithUnequalLength(api frontend.API, a []frontend.Variable, b []frontend.Variable) {
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	padA := make([]frontend.Variable, maxLen-len(a))
	padB := make([]frontend.Variable, maxLen-len(b))
	for i := range padA {
		padA[i] = frontend.Variable(0)
	}
	for i := range padB {
		padB[i] = frontend.Variable(0)
	}
	a = append(a, padA...)
	b = append(b, padB...)

	numEqual := frontend.Variable(0)
	for i := 0; i < maxLen; i++ {
		numEqual = api.Add(numEqual, isEqual(api, a[i], b[i]))
	}

	api.AssertIsEqual(numEqual, maxLen)
}
