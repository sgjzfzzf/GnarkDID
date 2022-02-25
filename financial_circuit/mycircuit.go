package zk

import (
	"os"
	zk "zk/zkprove"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

/*
	This is the circuit defination. Users can modify this file and define their own circuit. This circuit needs to implement the "Define" method.
*/

// The constant parameters used in the circuit.
const MAXAGE uint = 200
const ALLOWED_MINAGE uint = 18
const ALLOWED_MAXAGE uint = 36
const MAXINCOME uint = 0xffffffff
const ALLOWED_MININCOME uint = 5000

// The public witness needs labels, while private witness doesn't.
type Circuit struct {
	Age       frontend.Variable
	Income    frontend.Variable
	Name      frontend.Variable
	Signature eddsa.Signature `gnark:"signature,public"`
	PublicKey eddsa.PublicKey `gnark:"pubKey,public"`
}

// The implement of "Define".
func (circuit *Circuit) Define(api frontend.API) error {
	params, err := twistededwards.NewEdCurve(api.Curve())
	if err != nil {
		return err
	}
	circuit.PublicKey.Curve = params
	maxAge := api.ConstantValue(MAXAGE)
	allowedMaxAge := api.ConstantValue(ALLOWED_MAXAGE)
	allowedMinAge := api.ConstantValue(ALLOWED_MINAGE)
	maxIncome := api.ConstantValue(MAXINCOME)
	allowedMinIncome := api.ConstantValue(ALLOWED_MININCOME)
	hasher, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hasher.Write(circuit.Age, circuit.Income, circuit.Name, circuit.PublicKey.A.X, circuit.PublicKey.A.Y)
	hSum := hasher.Sum()
	// Verify the signature.
	err = eddsa.Verify(api, circuit.Signature, hSum, circuit.PublicKey)
	// Add constraints.
	api.AssertIsLessOrEqual(circuit.Age, allowedMaxAge)
	api.AssertIsLessOrEqual(api.Sub(maxAge, circuit.Age), api.Sub(maxAge, allowedMinAge))
	api.AssertIsLessOrEqual(api.Sub(maxIncome, circuit.Income), api.Sub(maxIncome, allowedMinIncome))

	jsonFile, err := os.Open("./financial_circuit/blacklist.json")
	if err != nil {
		return err
	}
	bannedUsers := BannedUsers{}
	bannedUsers.ReadJson(jsonFile)
	jsonFile.Close()
	for _, _name := range bannedUsers.Names {
		name := api.ConstantValue(zk.TransferStringHashToElement(_name))
		api.AssertIsDifferent(circuit.Name, name)
	}

	return nil
}
