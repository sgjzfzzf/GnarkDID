package zk

import (
	"hash"
	zk "zk/zkprove"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
)

/*
	This is the data structure helping to deal with the problems of circuit.
*/

type CircuitConstructor struct {
	Age       uint64
	Income    uint64
	Name      string
	Signature eddsa.Signature
	PublicKey eddsa.PublicKey
}

// Generate the digest of this circuit.
func (circuitConstructor *CircuitConstructor) GenerateDigest(hFunc hash.Hash) []byte {
	element := fr.NewElement(0)
	bytes := element.Bytes()
	element.SetUint64(circuitConstructor.Age)
	bytes = element.Bytes()
	hFunc.Write(bytes[:])
	element.SetUint64(circuitConstructor.Income)
	bytes = element.Bytes()
	hFunc.Write(bytes[:])
	element = zk.TransferStringHashToElement(circuitConstructor.Name)
	bytes = element.Bytes()
	hFunc.Write(bytes[:])
	bytes = circuitConstructor.PublicKey.A.X.Bytes()
	hFunc.Write(bytes[:])
	bytes = circuitConstructor.PublicKey.A.Y.Bytes()
	hFunc.Write(bytes[:])
	return hFunc.Sum([]byte{})
}

// Sign the circuit and generate the signature.
func (circuitConstructor *CircuitConstructor) GenerateSignature(hFunc hash.Hash, sk eddsa.PrivateKey) (eddsa.Signature, error) {
	hSum := circuitConstructor.GenerateDigest(hFunc)
	rawSign, err := sk.Sign(hSum, hFunc)
	if err != nil {
		return circuitConstructor.Signature, err
	}
	circuitConstructor.Signature.SetBytes(rawSign)
	return circuitConstructor.Signature, nil
}

// Generate the circuit.
func (circuitConstructor *CircuitConstructor) GenerateCircuit() Circuit {
	circuit := Circuit{}
	circuit.Age = circuitConstructor.Age
	circuit.Income = circuitConstructor.Income
	circuit.Name = zk.TransferStringHashToElement(circuitConstructor.Name)
	circuit.Signature.S = circuitConstructor.Signature.S[:]
	circuit.Signature.R.X = circuitConstructor.Signature.R.X
	circuit.Signature.R.Y = circuitConstructor.Signature.R.Y
	circuit.PublicKey.A.X = circuitConstructor.PublicKey.A.X
	circuit.PublicKey.A.Y = circuitConstructor.PublicKey.A.Y
	return circuit
}

// Generate the witness.
func (circuitConstructor *CircuitConstructor) GenerateWitness() (*witness.Witness, error) {
	circuit := circuitConstructor.GenerateCircuit()
	return frontend.NewWitness(&circuit, zk.SELECTED_CURVE_ID)
}
