package GnarkDID

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

func GeneratePVKey(r1cs frontend.CompiledConstraintSystem) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	return groth16.Setup(r1cs)
}

func SavePVKey(pk groth16.ProvingKey, vk groth16.VerifyingKey, keyName string) error {
	pkfile, err := os.Create(fmt.Sprintf("%s.pk", keyName))
	if err != nil {
		return err
	}
	defer pkfile.Close()
	vkfile, err := os.Create(fmt.Sprintf("%s.vk", keyName))
	if err != nil {
		return err
	}
	defer vkfile.Close()
	_, err = pk.WriteTo(pkfile)
	if err != nil {
		newerr := os.Remove(pkfile.Name())
		if newerr != nil {
			return newerr
		} else {
			return err
		}
	}
	_, err = vk.WriteTo(vkfile)
	if err != nil {
		newerr := os.Remove(vkfile.Name())
		if newerr != nil {
			return newerr
		} else {
			return err
		}
	}
	return nil
}

func GenerateSavePVKey(r1cs frontend.CompiledConstraintSystem, keyName string) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	pk, vk, err := GeneratePVKey(r1cs)
	if err != nil {
		return pk, vk, err
	}
	err = SavePVKey(pk, vk, keyName)
	if err != nil {
		return pk, vk, err
	}
	return pk, vk, nil
}

func ReadSavedPKey(file *os.File) (groth16.ProvingKey, error) {
	pk := groth16.NewProvingKey(ecc.BN254)
	_, err := pk.ReadFrom(file)
	return pk, err
}

func ReadSavedVKey(file *os.File) (groth16.VerifyingKey, error) {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err := vk.ReadFrom(file)
	return vk, err
}
