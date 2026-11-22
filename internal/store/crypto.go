package store

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
)

func randRead(b []byte) (int, error) { return rand.Read(b) }

func x509MarshalPKIX(pub *ecdsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}

func x509ParsePKIX(der []byte) (*ecdsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, x509.ErrUnsupportedAlgorithm
	}
	return pub, nil
}
