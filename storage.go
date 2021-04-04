package go_rsa_storage

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
)

type Storage struct {
	privateKey *rsa.PrivateKey
}

func NewStorage(key *rsa.PrivateKey) *Storage {
	s := &Storage{privateKey: key}
	return s
}

func (s *Storage) GenerateKey() (privateKey *rsa.PrivateKey, err error) {
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		err = errors.New(fmt.Sprintf("error when generate private key: %s", err))
		return
	}
	s.privateKey = privateKey
	_, err = s.PrivateKeyToPkcs1PEM()
	return
}

func (s *Storage) SetPrivateKey(key *rsa.PrivateKey) (err error) {
	s.privateKey = key
	_, err = s.PrivateKeyToPkcs1PEM()
	return
}

func (s *Storage) SetPrivateKeyFromPkcs1PemBytes(key []byte) (err error) {
	var block *pem.Block
	block, _ = pem.Decode(key)
	s.privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return
	}
	_, err = s.PrivateKeyToPkcs1PEM()
	return
}

func (s *Storage) SetPrivateKeyFromPkcs1PemFile(path string) (privateKey *rsa.PrivateKey, err error) {
	var bs []byte
	bs, err = ioutil.ReadFile(path)
	if err != nil {
		return
	}
	err = s.SetPrivateKeyFromPkcs1PemBytes(bs)
	if err == nil {
		privateKey = s.privateKey
	}
	return
}

func (s *Storage) PrivateKeyToPkcs1PEM() (privateKeyPem []byte, err error) {
	if s.privateKey == nil {
		err = errors.New("private key is not set, either call GenerateKey or SetPrivateKey manually")
		return
	}
	var privateKeyBytes []byte
	privateKeyBytes = x509.MarshalPKCS1PrivateKey(s.privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	var b bytes.Buffer
	err = pem.Encode(&b, privateKeyBlock)
	if err != nil {
		err = errors.New(fmt.Sprintf("error when encoding private key to pem: %s", err))
		return
	}
	privateKeyPem = b.Bytes()
	return
}

//
func (s *Storage) PublicKeyToPkcs1PEM(key *rsa.PublicKey) (publicKeyPem []byte, err error) {
	if key == nil {
		if s.privateKey == nil {
			err = errors.New("private key is not set, either call GenerateKey or SetPrivateKey manually")
			return
		}
		key = &s.privateKey.PublicKey
	}
	var publicKeyBytes []byte
	publicKeyBytes = x509.MarshalPKCS1PublicKey(key)
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	var b bytes.Buffer
	err = pem.Encode(&b, publicKeyBlock)
	if err != nil {
		err = errors.New(fmt.Sprintf("error when encoding public key to pem: %s", err))
		return
	}
	publicKeyPem = b.Bytes()
	return
}

//
func (s *Storage) PublicKeyToPkix1PEM(key *rsa.PublicKey) (publicKeyPem []byte, err error) {
	if key == nil {
		if s.privateKey == nil {
			err = errors.New("private key is not set, either call GenerateKey or SetPrivateKey manually")
			return
		}
		key = &s.privateKey.PublicKey
	}
	var publicKeyBytes []byte
	publicKeyBytes, err = x509.MarshalPKIXPublicKey(key)
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	var b bytes.Buffer
	err = pem.Encode(&b, publicKeyBlock)
	if err != nil {
		err = errors.New(fmt.Sprintf("error when encoding public key to pem: %s", err))
		return
	}
	publicKeyPem = b.Bytes()
	return
}

func (s *Storage) StorePrivateKeyPkcs1Pem(path string) (err error) {
	if s.privateKey == nil {
		err = errors.New("private key is not set, either call GenerateKey or SetPrivateKey manually")
		return
	}
	var bs []byte
	bs, err = s.PrivateKeyToPkcs1PEM()
	if err != nil {
		return
	}
	err = ioutil.WriteFile(path, bs, os.ModePerm)
	return
}

func (s *Storage) PublicKey() (key *rsa.PublicKey, err error) {
	if s.privateKey == nil {
		err = errors.New("private key is not set, either call GenerateKey or SetPrivateKey manually")
		return
	}
	key = &s.privateKey.PublicKey
	return
}

func (s *Storage) PublicKeyFromPkixPemBytes(bs []byte) (key *rsa.PublicKey, err error) {
	var block *pem.Block
	block, _ = pem.Decode(bs)

	var pub interface{}
	pub, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		err = errors.New(fmt.Sprintf("error when parsing public pem: %s", err))
		return
	}
	key = pub.(*rsa.PublicKey)
	return
}

func (s *Storage) PublicKeyFromPkcs1PemBytes(bs []byte) (key *rsa.PublicKey, err error) {
	var block *pem.Block
	block, _ = pem.Decode(bs)

	key, err = x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		err = errors.New(fmt.Sprintf("error when parsing public pem: %s", err))
		return
	}
	return
}

func (s *Storage) PublicKeyFromPkixPemPath(path string) (key *rsa.PublicKey, err error) {
	var bs []byte
	bs, err = ioutil.ReadFile(path)
	if err != nil {
		return
	}
	key, err = s.PublicKeyFromPkixPemBytes(bs)
	return
}

func (s *Storage) PublicKeyFromPkcs1PemPath(path string) (key *rsa.PublicKey, err error) {
	var bs []byte
	bs, err = ioutil.ReadFile(path)
	if err != nil {
		return
	}
	key, err = s.PublicKeyFromPkcs1PemBytes(bs)
	return
}

// if you pass nil to key, privatekey's public key will be used
func (s *Storage) PublicEncryptPkcs1(key *rsa.PublicKey, data []byte) (encrypted []byte, err error) {
	if key == nil {
		if s.privateKey == nil {
			err = errors.New("private key is not set, either call GenerateKey or SetPrivateKey manually")
			return
		}
		key = &s.privateKey.PublicKey
	}
	encrypted, err = rsa.EncryptPKCS1v15(rand.Reader, key, data)
	return
}

func (s *Storage) PrivateDecryptPkcs1(data []byte) (decrypted []byte, err error) {
	if s.privateKey == nil {
		err = errors.New("private key is not set, either call GenerateKey or SetPrivateKey manually")
		return
	}
	decrypted, err = rsa.DecryptPKCS1v15(rand.Reader, s.privateKey, data)
	return
}
