package circuit

import "github.com/consensys/gnark/frontend"

const MaxKeyLen = 25
const OneYearUnix = 31536000

// Dict
type PhDProfile struct {
	Status       String              //One of the Set
	ProgramYear  Integer             //Number within range
	StudentID    String              //meet format
	Publications []Publication //Append only
	Duration     TimeRange           //time sensitive
}

// Dict
type Publication struct {
	Title String
	Year  Integer
}

// Dict
type TimeRange struct {
	Start Integer
	End   Integer
}

type CovidRecord struct {
	LatestVaccine          Vaccine
	CovidTest              []CovidTest //append only
	CovidTestNumber        String      //meet certain format
	MedicalInsuranceStatus String      //one of the Set
	CoverageEndDate        Integer     //time sensitive
}
type Vaccine struct {
	VaccineType String  // One of the Set
	Dosage      Integer // Number within range
}
type CovidTest struct {
	TestDate Integer // time sensitive, must be increasing
	Result   String
}

type PhdLimit struct {
	StatusSet    [4]String
	YearRange    [2]frontend.Variable //[0] lowerbound, [1] upperbound
	Format       []frontend.Variable
	TimeMinRange Integer // minimum number of year of PhD program in year
}
type CovidLimit struct {
	VaccineTypeSet            []String
	DosageMax                 frontend.Variable
	MedicalInsuranceStatusSet []String
	CoverageMaxEndDate        Integer //vaccine can only coverage within a certain time
	Format                    []frontend.Variable
}
