package jwt_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"github.com/CarsonSlovoka/go-jwt"
	"testing"
)

func TestToken_SignedBytes_hmac(t *testing.T) {
	token := jwt.NewWithClaims(jwt.SigningMethodHMAC256, jwt.MapClaims{})
	privateKey := []byte("helloWorld")
	signedBytes, err := token.SignedBytes(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	parts := bytes.Split(signedBytes, []byte{'.'})
	if len(parts) != 3 {
		t.Fatal()
	}
	if err = token.SigningMethod.Verify(
		signedBytes[:bytes.LastIndexByte(signedBytes, '.')],
		parts[2],
		privateKey,
	); err != nil {
		t.Fatal(err)
	}
}

func TestToken_SignedBytes_rsa(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	token := jwt.NewWithClaims(jwt.SigningMethodRSA512, jwt.MapClaims{})
	signedBytes, err := token.SignedBytes(rsaKey)
	if err != nil {
		t.Fatal(err)
	}

	parts := bytes.Split(signedBytes, []byte{'.'})
	if len(parts) != 3 {
		t.Fatal()
	}
	if err = token.SigningMethod.Verify(
		signedBytes[:bytes.LastIndexByte(signedBytes, '.')],
		parts[2],
		&rsaKey.PublicKey,
	); err != nil {
		t.Fatal(err)
	}
}
