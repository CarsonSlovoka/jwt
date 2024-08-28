package jwt_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"github.com/CarsonSlovoka/go-jwt"
	"github.com/CarsonSlovoka/go-jwt/parser"
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
	signature, err := base64.RawURLEncoding.DecodeString(string(parts[2]))
	if err != nil {
		t.Fatal(err)
	}
	if err = token.SigningMethod.Verify(
		signedBytes[:bytes.LastIndexByte(signedBytes, '.')],
		signature,
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
	signature, err := base64.RawURLEncoding.DecodeString(string(parts[2]))
	if err != nil {
		t.Fatal(err)
	}
	if err = token.SigningMethod.Verify(
		signedBytes[:bytes.LastIndexByte(signedBytes, '.')],
		signature,
		&rsaKey.PublicKey,
	); err != nil {
		t.Fatal(err)
	}
}

func TestNew_ed25519(t *testing.T) {
	token := jwt.New(&jwt.SigningMethodED25519{})
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	bsToken, err := token.SignedBytes(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	vdFunc, err := parser.New().Parse(string(bsToken), func(method string) (jwt.ISigningMethod, error) {
		return &jwt.SigningMethodED25519{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if err = vdFunc(nil, nil, func(token *jwt.Token) (key any, err error) {
		return publicKey, nil
	}); err != nil {
		t.Fatal(err)
	}
}
