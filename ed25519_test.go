package jwt_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"github.com/CarsonSlovoka/go-jwt"
	"testing"
)

func TestSigningMethodED25519_Verify(t *testing.T) {
	m := jwt.SigningMethodED25519{}
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	msg := []byte("hello")
	signature, err := m.Sign(msg, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if err = m.Verify(msg, signature, publicKey); err != nil {
		t.Fatal()
	}

	if err = m.Verify([]byte("another msg"), signature, publicKey); err == nil {
		t.Fatal()
	}
	if !errors.Is(err, jwt.ErrEd25519Verification) || !errors.Is(err, jwt.ErrSignatureInvalid) {
		t.Fatal()
	}
}
