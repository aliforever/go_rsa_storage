package tests

import (
	"fmt"
	"testing"

	"github.com/aliforever/go_rsa_storage"
)

func TestGenerate(t *testing.T) {
	s := go_rsa_storage.NewStorage(nil)
	_, err := s.GenerateKey()
	if err != nil {
		fmt.Println(err)
		return
	}
	err = s.StorePrivateKeyPkcs1Pem("private.pem")
	if err != nil {
		fmt.Println(err)
		return
	}
	key, err := s.SetPrivateKeyFromPkcs1PemFile("private.pem")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(key)
}
