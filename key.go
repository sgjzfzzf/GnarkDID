package GnarkDID

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
)

func GenerateKey(seed io.Reader) (eddsa.PrivateKey, eddsa.PublicKey, error) {
	sk, err := eddsa.GenerateKey(seed)
	return sk, sk.PublicKey, err
}

func SaveKey(sk eddsa.PrivateKey, pk eddsa.PublicKey, keyname string) error {
	file, err := os.Create(fmt.Sprintf("%s.bk", keyname))
	if err != nil {
		return err
	}
	file.Write(sk.Bytes())
	file.Close()
	file, err = os.Create(fmt.Sprintf("%s.bk.pub", keyname))
	if err != nil {
		return err
	}
	file.Write(pk.Bytes())
	if err != nil {
		return err
	}
	return nil
}

func GenerateSaveKey(seed io.Reader, keyname string) (eddsa.PrivateKey, eddsa.PublicKey, error) {
	sk, pk, err := GenerateKey(seed)
	if err != nil {
		return sk, pk, err
	}
	err = SaveKey(sk, pk, keyname)
	if err != nil {
		return sk, pk, err
	}
	return sk, pk, nil
}

func ReadSavedPrivateKey(file *os.File) (eddsa.PrivateKey, error) {
	sk := eddsa.PrivateKey{}
	skbin, err := ioutil.ReadAll(file)
	if err != nil {
		return sk, err
	}
	sk.SetBytes(skbin)
	return sk, nil
}

func ReadSavedPublicKey(file *os.File) (eddsa.PublicKey, error) {
	pk := eddsa.PublicKey{}
	pkbin, err := ioutil.ReadAll(file)
	if err != nil {
		return pk, err
	}
	pk.SetBytes(pkbin)
	return pk, nil
}
