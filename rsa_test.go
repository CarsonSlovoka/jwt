package jwt_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"github.com/CarsonSlovoka/go-jwt"
	"testing"
)

func TestGenerateTokenFromRSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signedBytes, err := jwt.GenerateTokenFromRSA(testClaims, rsaKey)
	if err != nil {
		t.Fatal(err)
	}

	parts := bytes.Split(signedBytes, []byte{'.'})
	if len(parts) != 3 {
		t.Fatal()
	}
	signature := parts[2]
	if err = jwt.VerifyRSA(crypto.SHA512,
		bytes.Join([][]byte{parts[0], parts[1]}, []byte{'.'}),
		signature,
		&rsaKey.PublicKey,
	); err != nil {
		t.Fatal(err)
	}
}
