package GnarkDID

import (
	"crypto/sha256"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TransferStringHashToElement(str string) fr.Element {
	hasher := sha256.New()
	bytes := hasher.Sum([]byte(str))
	element := fr.NewElement(0)
	element.SetBytes(bytes)
	return element
}
