package jwt_test

import (
	"bytes"
	"crypto"
	"github.com/CarsonSlovoka/go-jwt"
	"testing"
	"time"
)

var testClaims = map[string]any{
	"iss": "https://www.example.com",
	"sub": "user-XXX",
	"aud": []string{"example-app1", "example-app2"},
	"jti": "unique-token-id-12345",
	"exp": time.Now().Add(time.Minute * 30).Unix(),
	"iat": time.Now().Unix(),
	"nbf": time.Now().Add(-time.Hour * 24 * 3).Unix(),
}

// http://jwt.io/
func TestGenerateTokenFromHMAC(t *testing.T) {
	privateKey := []byte("helloWorld")
	signedBytes, err := jwt.GenerateTokenFromHMAC(testClaims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	parts := bytes.Split(signedBytes, []byte{'.'})
	if len(parts) != 3 {
		t.Fatal()
	}
	signature := parts[2]
	if err = jwt.VerifyHMAC(crypto.SHA256,
		bytes.Join([][]byte{parts[0], parts[1]}, []byte{'.'}),
		signature,
		privateKey,
	); err != nil {
		t.Fatal(err)
	}
}
