package zk

import (
	"bufio"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

// The curve used is BN254.
const SELECTED_CURVE_ID ecc.ID = ecc.BN254

func SaveCircuit(r1cs frontend.CompiledConstraintSystem, name string) error {
	file, err := os.Create(fmt.Sprintf("%s.cir", name))
	defer file.Close()
	if err != nil {
		return err
	}
	writer := bufio.NewWriter(file)
	r1cs.WriteTo(writer)
	return nil
}

func ReadSavedCircuit(file *os.File) (frontend.CompiledConstraintSystem, error) {
	r1cs := groth16.NewCS(SELECTED_CURVE_ID)
	_, err := r1cs.ReadFrom(file)
	return r1cs, err
}
