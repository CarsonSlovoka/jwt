package jwt_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"github.com/CarsonSlovoka/go-jwt"
	"github.com/CarsonSlovoka/go-jwt/parser"
	"github.com/CarsonSlovoka/go-jwt/validator"
	"testing"
)

func TestNew_hmac(t *testing.T) {
	token := jwt.NewWithClaims(
		jwt.SigningMethodHMAC256,

		// 指定所有你想要的Claims
		// 如果要擴展可以用MapClaims或者自定義struct把RegisteredClaims加入，可以參考:
		// https://github.com/CarsonSlovoka/jwt/blob/5ff3ea21d7624f73baf3f2cd7c89ba5p a4129dedb/validator/validator_test.go#L11-L37
		jwt.RegisteredClaims{
			Issuer: "c.example.com",
		},
	)
	// token.Header["xx"] = "" // 如果有需要自定義Header可以後補上
	privateKey := []byte("key")
	bsSignature, err := token.SignedBytes(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	p := parser.New(func(v *validator.Validator) {
		v.ExpectedIssuer = "c.example.com"
		v.VerifyIat = true
	})
	vdFunc, err := p.Parse(string(bsSignature), func(method string) (jwt.ISigningMethod, error) {
		return jwt.SigningMethodHMAC256, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = vdFunc(nil, nil, func(token *jwt.Token) (key any, err error) {
		return privateKey, nil
	}); err != nil {
		t.Fatal(err)
	}
}

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

func TestNew_rsa(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	token := jwt.New(jwt.SigningMethodRSA256)
	bsSignature, err := token.SignedBytes(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	vdFunc, err := parser.New().Parse(
		string(bsSignature),
		func(method string) (jwt.ISigningMethod, error) {
			return jwt.SigningMethodRSA256, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err = vdFunc(nil, nil, func(token *jwt.Token) (key any, err error) {
		return &rsaKey.PublicKey, nil
	}); err != nil {
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

func TestNew_ecdsa(t *testing.T) {
	token := jwt.New(jwt.SigningMethodECDSA512)
	key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	bsToken, err := token.SignedBytes(key)
	if err != nil {
		t.Fatal(err)
	}

	vdFunc, err := parser.New().Parse(string(bsToken), func(method string) (jwt.ISigningMethod, error) {
		return jwt.SigningMethodECDSA512, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if err = vdFunc(nil, nil, func(token *jwt.Token) (any, error) {
		return &key.PublicKey, nil
	}); err != nil {
		t.Fatal(err)
	}
}
