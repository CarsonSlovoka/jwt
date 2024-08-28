package validator

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"github.com/CarsonSlovoka/go-jwt"
	"time"
)

// IClaimsValidator 這是為了讓使用者可以自定義特殊欄位的驗證
//
//	type MyCustomClaims struct {
//	    jwt.RegisteredClaims // 這個包含標準的方法，你就不需要再自定義
//	    Foo string `json:"foo"`
//	}
//
//	func (m MyCustomClaims) Validate() error { // 自定義你的驗證邏輯
//	    if m.Foo != "bar" {
//	        return errors.New("must be foobar")
//	    }
//	    return nil
//	}
type IClaimsValidator interface {
	jwt.IClaims
	Validate() error
}

type Validator struct {
	// timeFunc 驗證用的時間其基準，預設使用 time.Now()
	TimeFunc func() time.Time

	//require的項目表示，如果claims沒有提到此key，那麼是否要報錯
	RequireIssuer         bool // iss
	RequireSubject        bool // sub
	RequireAudience       bool // aud
	RequireExpirationTime bool // exp
	RequireNotBefore      bool // nbf
	RequireIssueAt        bool // iat

	// verify的項目，表示是否做該驗證
	VerifyIat bool

	ExpectedIssuer   string
	ExpectedSubject  string
	ExpectedAudience string
}

func (v *Validator) Validate(iClaims jwt.IClaims) error {
	var (
		now  time.Time
		errs = make([]error, 0, 6)
		err  error
	)

	if v.TimeFunc != nil {
		now = v.TimeFunc()
	} else {
		now = time.Now()
	}

	if err = v.verifyExpiresAt(iClaims, now, v.RequireExpirationTime); err != nil {
		errs = append(errs, err)
	}

	if err = v.verifyNotBefore(iClaims, now, v.RequireNotBefore); err != nil {
		errs = append(errs, err)
	}

	if v.VerifyIat {
		if err = v.verifyIssuedAt(iClaims, now, v.RequireIssueAt); err != nil {
			errs = append(errs, err)
		}
	}

	if v.ExpectedAudience != "" {
		if err = v.verifyAudience(iClaims, v.ExpectedAudience, v.RequireAudience); err != nil {
			errs = append(errs, err)
		}
	}

	if v.ExpectedIssuer != "" {
		if err = v.verifyIssuer(iClaims, v.ExpectedIssuer, v.RequireIssuer); err != nil {
			errs = append(errs, err)
		}
	}

	if v.ExpectedSubject != "" {
		if err = v.verifySubject(iClaims, v.ExpectedSubject, v.RequireSubject); err != nil {
			errs = append(errs, err)
		}
	}

	customValidator, ok := iClaims.(IClaimsValidator) // 如果此claim可以被轉型成此介面，就多跑他的驗證
	if ok {
		if err = customValidator.Validate(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) == 0 {
		return nil
	}

	return errors.Join(errs...)
}

// 目前的時間(now)必須在到期時間之前(exp)才會驗證通過
func (v *Validator) verifyExpiresAt(claims jwt.IClaims, now time.Time, required bool) (err error) {
	var exp *jwt.NumericDate
	exp, err = claims.GetExpirationTime() // 由傳入的jwt字串，可以解析出來明碼的部分，能得到exp
	if err != nil {
		return err
	}
	if exp == nil {
		if required {
			return fmt.Errorf("%w. key: %q", jwt.ErrClaimRequired, "exp")
		}
		return nil
	}
	if now.Before(exp.Time) {
		return nil
	}
	return jwt.ErrTokenExpired
}

// 當前的時間要在簽發的時間之後才算通過
func (v *Validator) verifyIssuedAt(claims jwt.IClaims, now time.Time, required bool) error {
	iat, err := claims.GetIssuedAt()
	if err != nil {
		return err
	}
	if iat == nil {
		if required {
			return fmt.Errorf("%w. key: %q", jwt.ErrClaimRequired, "iat")
		}
		return nil
	}
	if iat.Before(now) {
		return nil
	}
	return jwt.ErrTokenUsedBeforeIssued
}

// 當前的時間必須在定義的時間之後才算通過
func (v *Validator) verifyNotBefore(claims jwt.IClaims, now time.Time, required bool) error {
	nbf, err := claims.GetNotBefore()
	if err != nil {
		return err
	}

	if nbf == nil {
		if required {
			return fmt.Errorf("%w. key: %q", jwt.ErrClaimRequired, "iat")
		}
		return nil
	}

	if nbf.After(now) {
		return nil
	}
	return jwt.ErrTokenNotValidYet
}

// 只要傳進來的aud有其中一組與設定的匹配且非空字串，就算驗證通過
func (v *Validator) verifyAudience(claims jwt.IClaims, cmp string, required bool) error {
	var (
		aud []string
		err error
	)
	aud, err = claims.GetAudience()
	if err != nil {
		return err
	}

	if len(aud) == 0 {
		if required {
			return fmt.Errorf("%w. key: %q", jwt.ErrClaimRequired, "aud")
		}
		return nil
	}

	// use a var here to keep constant time compare when looping over a number of claims
	match := false
	var stringClaims string
	for _, a := range aud {
		if subtle.ConstantTimeCompare([]byte(a), []byte(cmp)) != 0 {
			match = true
			if len(a) > 0 { // 已經找到匹配的項目，且該值非空，即可馬上返回
				return nil
			}
		}
		stringClaims = stringClaims + a
	}

	// case where "" is sent in one or many aud claims
	if stringClaims == "" {
		if required {
			return fmt.Errorf("%w. key: %q", jwt.ErrClaimRequired, "aud")
		}
		return nil
	}

	if match {
		return nil
	}
	return jwt.ErrTokenInvalidAudience
}

func (v *Validator) verifyIssuer(claims jwt.IClaims, cmp string, required bool) error {
	iss, err := claims.GetIssuer()
	if err != nil {
		return err
	}

	if iss == "" {
		if required {
			return fmt.Errorf("%w. key: %q", jwt.ErrClaimRequired, "iss")
		}
		return nil
	}

	if iss == cmp {
		return nil
	}
	return jwt.ErrTokenInvalidIssuer
}

func (v *Validator) verifySubject(claims jwt.IClaims, cmp string, required bool) error {
	sub, err := claims.GetSubject()
	if err != nil {
		return err
	}

	if sub == "" {
		if required {
			return fmt.Errorf("%w. key: %q", jwt.ErrClaimRequired, "sub")
		}
		return nil
	}

	if sub == cmp {
		return nil
	}
	return jwt.ErrTokenInvalidSubject
}
