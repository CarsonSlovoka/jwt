package validator_test

import (
	"errors"
	"fmt"
	"github.com/CarsonSlovoka/go-jwt"
	"github.com/CarsonSlovoka/go-jwt/parser"
	"testing"
)

type MyCustomClaims struct {
	jwt.RegisteredClaims // 這個包含標準的方法，你就不需要再自定義

	// 以下為自定義的屬性
	Foo string `json:"foo"`
}

var ErrorMustBeFoo = errors.New("must be foo")

// Validate implements the IClaimsValidator interface.
func (m MyCustomClaims) Validate() error { // 自定義你的驗證邏輯
	if m.Foo != "foo" {
		return ErrorMustBeFoo
	}
	return nil
}

func TestValidator_Validate(t *testing.T) {
	key := []byte("my private key")
	// 模擬取得server簽名後的產物
	token := jwt.NewWithClaims(jwt.SigningMethodHMAC256, &MyCustomClaims{
		Foo: "bar", // 此驗證被定義為foo才是正確的，我們故意改成bar，使其觸發 ErrorMustBeFoo 來確保驗證真的有被執行到
	})
	bsToken, err := token.SignedBytes(key)
	if err != nil {
		t.Fatal(err)
	}

	// 模擬client送給server驗證的過程
	p := parser.New()
	// 如果你自定義Claims，請用ParseWithClaims，這樣他才會接自定義的驗證，否則會使用mapClaims，就不會跑自動驗證:
	// https://github.com/CarsonSlovoka/jwt/blob/d59b5602a018188985e96188957e7dbd1bec3af6/validator/validator.go#L94-L99
	vdFunc, err := p.ParseWithClaims(string(bsToken), func(method string) (jwt.ISigningMethod, error) {
		return jwt.SigningMethodHMAC256, nil
	}, &MyCustomClaims{})
	if err != nil {
		t.Fatal(err)
	}

	if err = vdFunc(nil, nil, func(token *jwt.Token) (any, error) {
		return key, nil
	}); !errors.Is(err, ErrorMustBeFoo) {
		t.Fatal("must fatal")
	}
}

type MyCustomClaims2 struct {
	jwt.RegisteredClaims
	Foo string `json:"foo"`
}

// 此範例與 TestValidator_Validate 很像，只是這次自訂的struct，不實作Validate
// 因此若也要達到相同的效果，就要在給 vdCustomClaimsFunc
func TestValidator_Validate2(t *testing.T) {
	key := []byte("my private key")
	token := jwt.NewWithClaims(jwt.SigningMethodHMAC256, &MyCustomClaims2{
		Foo: "bar",
	})
	bsToken, err := token.SignedBytes(key)
	if err != nil {
		t.Fatal(err)
	}

	p := parser.New()
	vdFunc, err := p.ParseWithClaims(string(bsToken), func(method string) (jwt.ISigningMethod, error) {
		return jwt.SigningMethodHMAC256, nil
	}, &MyCustomClaims2{})
	if err != nil {
		t.Fatal(err)
	}
	vdCustomClaimsFunc := func(iClaims jwt.IClaims) error {
		claims, ok := iClaims.(*MyCustomClaims2)
		if !ok {
			return fmt.Errorf("type error. expected: *MyCustomClaims, got: %T", iClaims)
		}
		if claims.Foo != "foo" {
			return ErrorMustBeFoo
		}
		return nil
	}

	if err = vdFunc(nil, vdCustomClaimsFunc,
		func(token *jwt.Token) (any, error) {
			return key, nil
		}); !errors.Is(err, ErrorMustBeFoo) {
		t.Fatal("must fatal")
	}
}

// 使用 MapClaims 來對自定義 Claims 內容做驗證
func TestValidator_Validate3(t *testing.T) {
	key := []byte("my private key")
	token := jwt.NewWithClaims(jwt.SigningMethodHMAC256, &jwt.MapClaims{
		"foo": "bar",
	})
	bsToken, err := token.SignedBytes(key)
	if err != nil {
		t.Fatal(err)
	}

	p := parser.New()
	// 因為我們使用MapClaims，所以不需要在用ParseWithClaims讓它曉得型別
	vdFunc, err := p.Parse(string(bsToken), func(method string) (jwt.ISigningMethod, error) {
		return jwt.SigningMethodHMAC256, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	vdCustomClaimsFunc := func(iClaims jwt.IClaims) error {
		claims, ok := iClaims.(*jwt.MapClaims)
		if !ok {
			return fmt.Errorf("type error. expected: *MyCustomClaims, got: %T", iClaims)
		}
		if (*claims)["foo"].(string) != "foo" {
			return ErrorMustBeFoo
		}
		return nil
	}

	if err = vdFunc(nil, vdCustomClaimsFunc,
		func(token *jwt.Token) (any, error) {
			return key, nil
		}); !errors.Is(err, ErrorMustBeFoo) {
		t.Fatal("must fatal")
	}
}
