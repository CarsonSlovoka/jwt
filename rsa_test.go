package jwt_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"github.com/CarsonSlovoka/go-jwt"
	"testing"
)

func TestSigningMethodRSA_Sign(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signedBytes, err := jwt.GenerateToken(jwt.SigningMethodRSA256, testClaims, rsaKey)
	if err != nil {
		t.Fatal(err)
	}

	parts := bytes.Split(signedBytes, []byte{'.'})
	if len(parts) != 3 {
		t.Fatal()
	}
	signature := parts[2]

	if err = jwt.SigningMethodRSA256.Verify(
		bytes.Join([][]byte{parts[0], parts[1]}, []byte{'.'}),
		signature,
		&rsaKey.PublicKey); err != nil {
		t.Fatal(err)
	}
}
