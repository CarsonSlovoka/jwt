package jwt_test

import (
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
func TestSigningMethodHMAC_Verify(t *testing.T) {
	m := jwt.SigningMethodHMAC256
	privateKey := []byte("my key")
	signature, err := m.Sign([]byte("Hello"), privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if err = m.Verify([]byte("Hello"), signature, privateKey); err != nil {
		t.Fatal()
	}
}
