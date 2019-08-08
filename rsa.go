package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
)

// MethodRSA is used for Siging and Verifying JWT.
type MethodRSA struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewMethodRSA creates *MethodRSA that takes in RS256 PCKS#1
// encoded pem public and private keys as io.Reader.
func NewMethodRSA(privKey, pubKey io.Reader) (*MethodRSA, error) {
	buf, err := ioutil.ReadAll(privKey)
	if err != nil {
		return nil, err
	}
	prv, err := privateKeyFromPem(buf)
	if err != nil {
		return nil, err
	}

	buf, err = ioutil.ReadAll(pubKey)
	if err != nil {
		return nil, err
	}
	pub, err := publicKeyFromPem(buf)
	if err != nil {
		return nil, err
	}

	return &MethodRSA{
		privateKey: prv,
		publicKey:  pub,
	}, nil
}

func privateKeyFromPem(pemFile []byte) (*rsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode(pemFile)
	if pemBlock == nil {
		return nil, fmt.Errorf("error decoding key")
	}
	key, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		// We write a custom error here because returned error from the
		// the method is not very useful
		return nil, fmt.Errorf("key %T must be a PKCS#1 PEM encoded key", key)
	}

	return key, nil
}

func publicKeyFromPem(pemFile []byte) (*rsa.PublicKey, error) {
	pemBlock, _ := pem.Decode(pemFile)
	if pemBlock == nil {
		return nil, fmt.Errorf("error decoding key")
	}
	key, err := x509.ParsePKCS1PublicKey(pemBlock.Bytes)
	if err != nil {
		// We write a custom error here because returned error from the
		// the method is not very useful.
		return nil, fmt.Errorf("key %T must be a PKCS#1 PEM encoded key", key)
	}

	return key, nil
}

// Sign signs JWT with RS256 algorithm and PKCS#1 pem key.
func (r *MethodRSA) Sign(bytesToSign io.Reader) ([]byte, error) {
	buf, err := ioutil.ReadAll(bytesToSign)
	if err != nil {
		return nil, err
	}

	hash := sha256.New()
	hash.Write(buf)
	digest := hash.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, r.privateKey, crypto.SHA256, digest)
}

// Verify verifies bytesToVerify using a RS256 signature.
// Returns error if verification is failed.
func (r *MethodRSA) Verify(bytesToVerify, signature io.Reader) error {
	buf, err := ioutil.ReadAll(bytesToVerify)
	if err != nil {
		return err
	}

	sig, err := ioutil.ReadAll(signature)
	if err != nil {
		return err
	}

	hash := sha256.New()
	hash.Write(buf)
	digest := hash.Sum(nil)
	return rsa.VerifyPKCS1v15(r.publicKey, crypto.SHA256, digest, sig)
}
