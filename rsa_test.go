package jwt_test

import (
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
	m := jwt.SigningMethodRSA256
	msg := []byte("hello")
	signature, err := m.Sign(msg, rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Verify(msg, signature, &rsaKey.PublicKey); err != nil {
		t.Fatal(err)
	}
}
