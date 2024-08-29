package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/CarsonSlovoka/jwt"
	"testing"
)

func TestSigningMethodECDSA_Verify(t *testing.T) {
	msg := []byte("hello")
	for i, tt := range []struct {
		method *jwt.SigningMethodECDSA
		curve  elliptic.Curve
	}{
		{jwt.SigningMethodECDSA256, elliptic.P256()},
		{jwt.SigningMethodECDSA384, elliptic.P384()},
		{jwt.SigningMethodECDSA512, elliptic.P521()},
	} {
		key, _ := ecdsa.GenerateKey(tt.curve, rand.Reader)
		signature, err := tt.method.Sign(msg, key)
		if err != nil {
			t.Fatal(i, err)
		}
		if err = tt.method.Verify(msg, signature, &key.PublicKey); err != nil {
			t.Fatal(i, err)
		}
	}
}
