package jwt

import (
	"encoding/json"
	"fmt"
)

// Claims https://datatracker.ietf.org/doc/html/rfc7519#section-4.1 namely
// {exp, iat, nbf, iss, sub, aud}
// 之所以提供這個方法，只是為了在驗證的時候，可以避免用map打key的方式
// 另外因為驗證的時後claims我們能得到的資訊只有字串，所以這邊的工作還要負責把字串轉換成合適的型別
type Claims interface {
	GetExpirationTime() (*NumericDate, error)
	GetIssuedAt() (*NumericDate, error)
	GetNotBefore() (*NumericDate, error)
	GetIssuer() (string, error)
	GetSubject() (string, error)
	GetAudience() ([]string, error)
}

type MapClaims map[string]any

// GetExpirationTime implements the Claims interface.
func (m MapClaims) GetExpirationTime() (*NumericDate, error) {
	return m.parseNumericDate("exp")
}

// GetNotBefore implements the Claims interface.
func (m MapClaims) GetNotBefore() (*NumericDate, error) {
	return m.parseNumericDate("nbf")
}

// GetIssuedAt implements the Claims interface.
func (m MapClaims) GetIssuedAt() (*NumericDate, error) {
	return m.parseNumericDate("iat")
}

// GetAudience implements the Claims interface.
func (m MapClaims) GetAudience() (ClaimStrings, error) {
	return m.parseClaimsString("aud")
}

// GetIssuer implements the Claims interface.
func (m MapClaims) GetIssuer() (string, error) {
	return m.parseString("iss")
}

// GetSubject implements the Claims interface.
func (m MapClaims) GetSubject() (string, error) {
	return m.parseString("sub")
}

// 轉成日期, 如果key值沒有提供不算錯誤
func (m MapClaims) parseNumericDate(key string) (*NumericDate, error) {
	v, ok := m["exp"]
	if !ok {
		return nil, nil // 不算錯，因為有可能此欄位非必須，是否會錯交由外層判斷
	}
	switch exp := v.(type) {
	case float64:
		if exp == 0 {
			return nil, nil
		}
		return newNumericDateFromSeconds(exp), nil
	case json.Number:
		f64, err := exp.Float64()
		if err != nil {
			return nil, err
		}
		return newNumericDateFromSeconds(f64), nil
	}
	return nil, fmt.Errorf("%s is invalid %w", key, ErrInvalidType)
}

// parseClaimsString tries to parse a key in the map claims type as a
// [ClaimsStrings] type, which can either be a string or an array of string.
func (m MapClaims) parseClaimsString(key string) (ClaimStrings, error) {
	var cs []string
	switch v := m[key].(type) {
	case string:
		cs = append(cs, v)
	case []string:
		cs = v
	case []interface{}:
		for _, a := range v {
			vs, ok := a.(string)
			if !ok {
				return nil, fmt.Errorf("%s is invalid. %w", key, ErrInvalidType)
			}
			cs = append(cs, vs)
		}
	}
	return cs, nil
}

// parseString 如果key沒有提供，不算錯誤，是否錯誤將由後續自行決定
func (m MapClaims) parseString(key string) (string, error) {
	var (
		ok  bool
		raw interface{}
		iss string
	)
	raw, ok = m[key]
	if !ok {
		return "", nil
	}
	iss, ok = raw.(string)
	if !ok {
		return "", fmt.Errorf("%s is invalid. %w", key, ErrInvalidType)
	}
	return iss, nil
}
