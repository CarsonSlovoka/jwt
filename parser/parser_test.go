package parser_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/CarsonSlovoka/go-jwt"
	"github.com/CarsonSlovoka/go-jwt/parser"
	"github.com/CarsonSlovoka/go-jwt/validator"
	"slices"
	"testing"
)

func TestParser_Parse(t *testing.T) {
	token := jwt.NewWithClaims(jwt.SigningMethodRSA256, &jwt.RegisteredClaims{
		Issuer:   "auth.example.com",
		Subject:  "user123",
		Audience: jwt.ClaimStrings{"app.example.com", "foo.example.com"},
	})
	// token.Header["myCustomHeader"] = "..." // 預設會寫好alg, typ 如果有其他的內容，則要自己加

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	bsToken, err := token.SignedBytes(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	p := parser.New(
		// 設定基礎的驗證內容
		func(v *validator.Validator) {
			v.VerifyIat = true
			v.ExpectedIssuer = "auth.example.com"
			v.ExpectedSubject = "user123"
			v.ExpectedAudience = "foo.example.com"
		},
	)

	getSigningMethod := func(method string) (jwt.ISigningMethod, error) {
		if method == jwt.SigningMethodRSA256.Name {
			return jwt.SigningMethodRSA256, nil
		}
		return nil, fmt.Errorf("unsupport method: %q", method)
	}

	// outClaims := &jwt.MapClaims{}
	vdFunc, err := p.ParseWithClaims(string(bsToken),
		getSigningMethod,
		nil, // outClaims, // 如果不需要取得，可以不用給
	)
	if err != nil {
		t.Fatal(err)
	}

	keyFunc := func(token *jwt.Token) (key any, err error) {
		switch token.SigningMethod.AlgName() {
		case jwt.SigningMethodRSA256.Name, jwt.SigningMethodRSA512.Name: // 假設這些算法都對應到同一組公鑰
			// return []crypto.PublicKey{&rsaKey.PublicKey}, nil // 多把公鑰範例
			return &rsaKey.PublicKey, nil // 單一公鑰
		}
		return nil, fmt.Errorf("unsupport signing method: %q", token.SigningMethod.AlgName())
	}

	headerChecker := func(h map[string]any) error {
		// h["typ"] == "JWT" // 不需要再寫，這點程式會自動在前置的時候就進行判斷

		// 可以新增alg的驗證，例如只支援這幾種演算法
		if slices.Contains(
			[]string{jwt.SigningMethodRSA256.Name, jwt.SigningMethodRSA512.Name},
			h["alg"].(string),
		) {
			return nil
		}
		return fmt.Errorf("unsupport header alg: %q", h["alg"].(string))
	}

	if err = vdFunc(headerChecker, // 如果header沒有什麼特別的，可以不需要寫
		nil, // 若無特殊的claims驗證，也可以不需要給
		keyFunc,
	); err != nil {
		t.Fatal(err)
	}
}
