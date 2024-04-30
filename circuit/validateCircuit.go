package circuit

import "github.com/consensys/gnark/frontend"

func Validate(api frontend.API, content PhDProfile, record []frontend.Variable, CommittedKey frontend.Variable, Key frontend.Variable, minYearNum frontend.Variable) {
	api.AssertIsEqual(CommittedKey, commit(api, Key))
	assertArrayEqualWithUnequalLength(api, record, encrypt(api, Key, encodePhdProfile(api, content)))
	api.AssertIsLessOrEqual(minYearNum, content.ProgramYear.X)
}
