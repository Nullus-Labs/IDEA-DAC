package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"runtime"
	"strconv"
	"time"
	_ "time"

	circuit "github.com/Nullus-Labs/IDEA-DAC/circuit"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// const MaxPub = 3
const BlkLen = 31
const MaxRecLen = 100
const MaxStrLen = 20
const MaxTitleLen = 100
const MaxDepth = 3
const IDLength = 5

type String = circuit.String
type Integer = circuit.Integer
type Publication = circuit.Publication
type PhDProfile = circuit.PhDProfile
type PhdLimit = circuit.PhdLimit
type TimeRange = circuit.TimeRange

type PhDProfileJSON struct {
	Status       string            `json:"status"`
	ProgramYear  int64             `json:"programYear"`
	StudentID    string            `json:"studentID"`
	Publications []PublicationJSON `json:"publications"`
	Duration     TimeRangeJSON     `json:"duration"`
}

type PublicationJSON struct {
	Title string `json:"title"`
	Year  int64  `json:"year"`
}

type TimeRangeJSON struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}

type PhdEditCircuit struct {
	OldRecord    []frontend.Variable `gnark:",public"`
	NewRecord    []frontend.Variable `gnark:",public"`
	Limit        PhdLimit            `gnark:",public"`
	CommittedKey frontend.Variable   `gnark:",public"`
	OldContent   PhDProfile
	NewContent   PhDProfile
	Key          frontend.Variable
}

func (c *PhdEditCircuit) Define(api frontend.API) error {
	circuit.EditCheckPhd(api, c.OldRecord[:], c.NewRecord[:], c.Limit, c.CommittedKey, c.OldContent, c.NewContent, c.Key)
	return nil
}

func main() {
	MaxPub, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic(err)
	}
	runtime.GOMAXPROCS(runtime.NumCPU())
	fmt.Println("Number of CPUs:", runtime.NumCPU())
	file, err := os.OpenFile("fast_phd_info_large.csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()
	circ := initPhdEditCircuit(MaxPub)

	var record []int

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circ)
	if err != nil {
		panic(err)
	}
	record = append(record, cs.GetNbConstraints())

	setupStartTime := time.Now()
	pk, vk, err := groth16.Setup(cs)
	setupElapsedTime := time.Since(setupStartTime)
	record = append(record, int(setupElapsedTime.Milliseconds()))
	if err != nil {
		panic(err)
	}
	f, _ := os.OpenFile("phdEditVerifier.sol", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	err = vk.ExportSolidity(f)
	if err != nil {
		panic(err)
	}
	assignment := initPhdEditCircuit(MaxPub)
	assignment = getAssignment(assignment, MaxPub)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	witnessPub, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		panic(err)
	}

	proofStartTime := time.Now()
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		panic(err)
	}
	proofElapsedTime := time.Since(proofStartTime)
	record = append(record, int(proofElapsedTime.Milliseconds()))

	verifyStartTime := time.Now()
	err = groth16.Verify(proof, vk, witnessPub)
	if err != nil {
		panic(err)
	}
	verifyElapsedTime := time.Since(verifyStartTime)
	record = append(record, int(verifyElapsedTime.Milliseconds()))

	writer.Write([]string{strconv.Itoa(MaxPub), strconv.Itoa(record[0]), strconv.Itoa(record[1]), strconv.Itoa(record[2]), strconv.Itoa(record[3])})
}

func getAssignment(res PhdEditCircuit, MaxPub int) PhdEditCircuit {
	oldEnc, oldProfile := ReadJSON("oldProfile.json")
	newEnc, newProfile := ReadJSON("newProfile.json")
	res.OldContent = MakePhdProfile(oldProfile, MaxPub)
	res.NewContent = MakePhdProfile(newProfile, MaxPub)

	//limit
	res.Limit = PhdLimit{
		StatusSet: [4]String{MakeString("Approved"),
			MakeString("Ongoing"),
			MakeString("Graduated"),
			MakeString("Failed")},
		YearRange:    [2]frontend.Variable{0, 10},
		Format:       []frontend.Variable{1, 1, 1, 3, 3},
		TimeMinRange: MakeInteger(3, 1),
	}

	//Key and committed Key
	encryptKey, _ := new(fr.Element).SetString("0x52fdfc072182654f163f5f0f9a621d729566c74d10037c4d")
	res.Key = encryptKey.BigInt(new(big.Int))
	res.CommittedKey = circuit.CommitMiMC(res.Key.(*big.Int).Bytes())
	oldRec := EncryptRec(oldEnc, encryptKey)
	newRec := EncryptRec(newEnc, encryptKey)
	res.OldRecord = make([]frontend.Variable, MaxRecLen)
	res.NewRecord = make([]frontend.Variable, MaxRecLen)

	for i := 0; i < MaxRecLen; i++ {
		if i < len(oldRec) {
			res.OldRecord[i] = oldRec[i]
		} else {
			res.OldRecord[i] = 0 //circuit.DUMMY
		}
		if i < len(newRec) {
			res.NewRecord[i] = newRec[i]
		} else {
			res.NewRecord[i] = 0 //circuit.DUMMY
		}
	}

	return res
}

func MakeString(input string) String {
	ascii := circuit.StringToAscii(input)
	x := make(String, MaxStrLen)
	x[0] = len(ascii)
	for i := 1; i < len(ascii)+1; i++ {
		x[i] = ascii[i-1]
	}
	for i := len(ascii) + 1; i < MaxStrLen; i++ {
		x[i] = circuit.DUMMY
	}
	return x
}

func MakeTitle(input string) String {
	ascii := circuit.StringToAscii(input)
	x := make(String, MaxTitleLen)
	x[0] = len(ascii)
	for i := 1; i < len(ascii)+1; i++ {
		x[i] = ascii[i-1]
	}
	for i := len(ascii) + 1; i < MaxTitleLen; i++ {
		x[i] = circuit.DUMMY
	}
	return x
}

func MakeID(input string) String {
	ascii := circuit.StringToAscii(input)
	x := make(String, IDLength+1)
	x[0] = len(ascii)
	for i := 0; i < len(ascii); i++ {
		x[i+1] = ascii[i]
	}
	return x
}

func EmptyStringNormal() String {
	ret := make(String, MaxStrLen)
	ret[0] = 0
	for i := 1; i < MaxStrLen; i++ {
		ret[i] = circuit.DUMMY
	}
	return ret
}

func EmptyID() String {
	ret := make(String, IDLength+1)
	ret[0] = IDLength
	for i := 1; i < IDLength+1; i++ {
		ret[i] = circuit.DUMMY
	}
	return ret
}

func EmptyStringTitle() String {
	ret := make(String, MaxTitleLen)
	ret[0] = 0
	for i := 1; i < MaxTitleLen; i++ {
		ret[i] = circuit.DUMMY
	}
	return ret
}

func EmptyInteger(maxDigit ...int) Integer {
	if len(maxDigit) > 0 {
		return Integer{
			X:        0,
			MaxDigit: maxDigit[0]}
	} else {
		return Integer{
			X:        0,
			MaxDigit: 0}
	}
}

func EmptyPublication() Publication {
	return Publication{
		Title: EmptyStringTitle(),
		Year:  EmptyInteger(4)}
}

func MakeInteger(x int64, maxDigit int) Integer {
	return Integer{
		X:        frontend.Variable(x),
		MaxDigit: maxDigit}
}

func MakeTimeRange(start int64, end int64) TimeRange {
	return TimeRange{
		Start: MakeInteger(start, 10),
		End:   MakeInteger(end, 10)}
}

func MakePublication(title string, year int64) Publication {
	return Publication{
		Title: MakeTitle(title),
		Year:  MakeInteger(year, 4)}
}

func MakePhdProfile(profile PhDProfileJSON, MaxPub int) PhDProfile {
	res := initPhdProfile(MaxPub)
	res.Status = MakeString(profile.Status)
	res.ProgramYear = MakeInteger(profile.ProgramYear, 1)
	res.Duration = MakeTimeRange(profile.Duration.Start, profile.Duration.End)
	res.StudentID = MakeID(profile.StudentID)
	res.Publications = make([]Publication, MaxPub)
	for i := 0; i < MaxPub; i++ {
		res.Publications[i] = EmptyPublication()
	}
	for i := 0; i < len(profile.Publications); i++ {
		res.Publications[i] = MakePublication(profile.Publications[i].Title, profile.Publications[i].Year)
	}

	return res
}

func ReadJSON(name string) ([]byte, PhDProfileJSON) {
	var profile PhDProfileJSON
	// Read the JSON file
	data, err := ioutil.ReadFile(name)
	if err != nil {
		panic(err)
	}
	var buf bytes.Buffer
	err = json.Compact(&buf, data)
	if err != nil {
		panic(err)
	}
	// Unmarshal the JSON data into the struct
	err = json.Unmarshal(data, &profile)
	if err != nil {
		panic(err)
	}
	return buf.Bytes(), profile
}

func EncryptRec(input []byte, key *fr.Element) []fr.Element {
	var res []fr.Element
	for i := 0; i < len(input); i += BlkLen {
		var end int
		if i+BlkLen > len(input) {
			end = len(input)
		} else {
			end = i + BlkLen
		}
		blk := new(fr.Element).SetBytes(reverseEndian(input[i:end]))
		res = append(res, circuit.EncryptMimcFr(*key, *blk))
	}
	return res
}

func reverseEndian(input []byte) []byte {
	res := make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		res[i] = input[len(input)-1-i]
	}
	return res
}

func initPhdEditCircuit(MaxPub int) PhdEditCircuit {
	res := PhdEditCircuit{}

	res.OldContent = initPhdProfile(MaxPub)
	res.NewContent = initPhdProfile(MaxPub)

	//limit
	res.Limit = initPhdLimit()

	res.Key = 0
	res.CommittedKey = 0

	res.OldRecord = make([]frontend.Variable, MaxRecLen)
	res.NewRecord = make([]frontend.Variable, MaxRecLen)
	for i := 0; i < MaxRecLen; i++ {
		res.OldRecord[i] = 0
		res.NewRecord[i] = 0
	}
	return res
}

func initPhdProfile(MaxPub int) PhDProfile {
	res := PhDProfile{}
	res.Status = EmptyStringNormal()
	res.ProgramYear = EmptyInteger(1)
	res.Duration = initTimeRange()
	res.StudentID = EmptyID()
	res.Publications = make([]Publication, MaxPub)
	for i := 0; i < MaxPub; i++ {
		res.Publications[i] = EmptyPublication()
	}
	return res
}

func initTimeRange() TimeRange {
	res := TimeRange{}
	res.Start = EmptyInteger(10)
	res.End = EmptyInteger(10)
	return res
}

func initPhdLimit() PhdLimit {
	res := PhdLimit{}
	res.StatusSet = [4]String{EmptyStringNormal(),
		EmptyStringNormal(),
		EmptyStringNormal(),
		EmptyStringNormal()}
	res.YearRange = [2]frontend.Variable{0, 0}

	res.Format = make([]frontend.Variable, IDLength)
	for i := 0; i < IDLength; i++ {
		res.Format[i] = 0
	}
	res.TimeMinRange = EmptyInteger(1)
	return res
}
