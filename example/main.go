package main

import (
	"fmt"
	"strings"

	zkcircuit "zk/financial_circuit"
	zkprove "zk/zkprove"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

/*
	Here is an example to show how to make use of this library to generate a proof and verify it.
*/
func main() {
	// Compile the circuit.
	r1cs, err := frontend.Compile(zkprove.SELECTED_CURVE_ID, backend.GROTH16, &zkcircuit.Circuit{})
	if err != nil {
		fmt.Println("Error: ", err)
	}
	// Save the circuit.
	// zkprove.SaveCircuit(r1cs, "mycircuit")

	// Define the paramters used in the proof.
	var age uint64 = 25
	var income uint64 = 10000
	var name string = "Edward"

	// Generate keys.
	sk, _, err := zkprove.GenerateKey(strings.NewReader("Hello, Gnark!"))
	// Save keys.
	// zkprove.SaveKey(sk, sk.PublicKey, "mykey")

	// Generate hasher.
	hFunc := mimc.NewMiMC()

	// Assgin the parameters
	circuitConstructor := zkcircuit.CircuitConstructor{}
	circuitConstructor.Age = age
	circuitConstructor.Income = income
	circuitConstructor.Name = name
	circuitConstructor.PublicKey = sk.PublicKey

	// Sign these parameters.
	_, err = circuitConstructor.GenerateSignature(hFunc, sk)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	// Generate witness used in proof.
	witness, err := circuitConstructor.GenerateWitness()
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}
	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	// Generate proof.
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Println("Prove error:", err)
		return
	}
	// Save the proof.
	// zkprove.SaveProof(proof, "myproof")

	// Verify the proof.
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println("Verify error:", err)
		return
	}
	fmt.Println("Success.")
}
