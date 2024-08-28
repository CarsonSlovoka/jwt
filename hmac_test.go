package jwt_test

import (
	"bytes"
	"github.com/CarsonSlovoka/go-jwt"
	"testing"
	"time"
)

var testClaims = jwt.MapClaims{
	"iss": "https://www.example.com",
	"sub": "user-XXX",
	"aud": []string{"example-app1", "example-app2"},
	"jti": "unique-token-id-12345",
	"exp": time.Now().Add(time.Minute * 30).Unix(),
	"iat": time.Now().Unix(),
	"nbf": time.Now().Add(-time.Hour * 24 * 3).Unix(),
}

// http://jwt.io/
func TestSigningMethodHMAC_Sign(t *testing.T) {
	privateKey := []byte("helloWorld")
	token := jwt.NewWithClaims(jwt.SigningMethodHMAC256, testClaims)
	signedBytes, err := token.SignedBytes(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	parts := bytes.Split(signedBytes, []byte{'.'})
	if len(parts) != 3 {
		t.Fatal()
	}
	signature := parts[2]
	if err = jwt.SigningMethodHMAC256.Verify(
		signedBytes[:bytes.LastIndexByte(signedBytes, '.')], signature, privateKey); err != nil {
		t.Fatal(err)
	}
}
