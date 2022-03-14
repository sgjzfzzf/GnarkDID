package GnarkDID

import (
	"fmt"
	"os"

	"github.com/consensys/gnark/backend/groth16"
)

func SaveProof(proof groth16.Proof, proofName string) (groth16.Proof, error) {
	file, err := os.Create(fmt.Sprintf("%s.proof", proofName))
	if err != nil {
		return proof, err
	}
	defer file.Close()
	_, err = proof.WriteTo(file)
	if err != nil {
		return proof, err
	}
	return proof, nil
}

func ReadSavedProof(file *os.File) (groth16.Proof, error) {
	proof := groth16.NewProof(SELECTED_CURVE_ID)
	proof.ReadFrom(file)
	return proof, nil
}
