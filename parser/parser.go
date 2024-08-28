package parser

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/CarsonSlovoka/go-jwt"
	"github.com/CarsonSlovoka/go-jwt/validator"
	"strings"
)

type Parser struct {
	// validator 由於Validator的欄位都公開，不希望Parser生成完畢還可以被異動，所以改用小寫字段
	validator *validator.Validator
}

// New 建立一個對象，只對驗證的內容做設定
// 預設只對Audience, Issuer, Subject做驗證
func New(options ...validator.Option) *Parser {
	p := &Parser{
		validator: &validator.Validator{
			RequireAudience: true,
			RequireIssuer:   true,
			RequireSubject:  true,
		},
	}

	for _, option := range options {
		option(p.validator)
	}
	return p
}

// Parse 細節請參考 ParseWithClaims
func (p *Parser) Parse(
	tokenStr string,
	getSigningMethod func(method string) (jwt.ISigningMethod, error),
) (
	vdFunc func(
		vdHeader func(header map[string]any) error,
		vdCustomClaims func(jwt.IClaims) error,
		kf jwt.KeyFunc,
	) error,
	err error,
) {
	return p.ParseWithClaims(tokenStr, getSigningMethod, nil)
}

// ParseWithClaims 其完成時，只是將傳入的jwt字串轉換成為jwt.Token對象
// 至於後面的驗證，需要自定義，請參考 Parser.validate
func (p *Parser) ParseWithClaims(
	tokenStr string,
	getSigningMethod func(method string) (jwt.ISigningMethod, error), // 自定義您server所提供的方法
	iClaims jwt.IClaims, // 此參數指的是讀取字串的Claims內容，將其保存在此 // 此為claims的格式，如果給nil，預設使用 jwt.MapClaims
) (
	vdFunc func(
		vdHeader func(header map[string]any) error,
		vdCustomClaims func(jwt.IClaims) error,
		kf jwt.KeyFunc,
	) error,
	err error,
) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token contains an invalid number of segments: %+v, %w", parts, jwt.ErrTokenMalformed)
	}
	// header
	var header map[string]any
	header, err = p.parseHeader(parts[0])
	if err != nil {
		return nil, err
	}
	token := &jwt.Token{Header: header}
	token.SigningMethod, err = getSigningMethod(token.Header["alg"].(string))
	if err != nil {
		return nil, err
	}

	// claims
	if iClaims == nil {
		iClaims = &jwt.MapClaims{}
	}
	if err = p.parseClaims(parts[1], iClaims); err != nil {
		return nil, err
	}
	token.Claims = iClaims

	// 這邊統一將signature解碼，不要在該演算法的Verify做這件事:
	// 1. 演算法只是提供驗證，所以不應該假設signature有被URLDecode
	// 2. 就算放在演算法裡寫，也要每一個演算法的Verify都要寫URLDecode相當麻煩
	var signature []byte // 通常特徵也會用URLEncoding，所以也要還原回去，才是之前算出來的特徵(之前加簽出來的內容)
	signature, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("could not base64 decode signature %w", err)
	}

	return func(
		validateHeader func(map[string]any) error,
		validateCustomClaims func(jwt.IClaims) error,
		keyFunc jwt.KeyFunc,
	) error {
		return p.validate(token, validateHeader, validateCustomClaims,
			[]byte(strings.Join(parts[0:2], ".")), signature, keyFunc)
	}, nil
}

func (p *Parser) validate(
	token *jwt.Token,
	validateHeader func(map[string]any) error,
	customValidate func(jwt.IClaims) error,
	signingBytes []byte, signature []byte, keyFunc jwt.KeyFunc,
) error {

	if keyFunc == nil {
		return fmt.Errorf("error keyFunc is nil. %w", jwt.ErrInvalidKeyType)
	}

	if validateHeader != nil {
		err := validateHeader(token.Header)
		if err != nil {
			return err
		}
	}

	if err := p.validator.Validate(token.Claims); err != nil {
		return err
	}

	keys, err := keyFunc(token)
	if err != nil {
		return fmt.Errorf(
			"error while executing keyfunc. %w",
			jwt.ErrTokenKeyFuncUnknown,
		)
	}

	switch key := keys.(type) {
	case []crypto.PublicKey:
		// 如果有多把keys就一把一把驗證，如果有找到匹配的就離開
		for _, k := range key {
			if err = token.SigningMethod.Verify(signingBytes, signature, k); err == nil {
				break
			}
		}
	default:
		err = token.SigningMethod.Verify(signingBytes, signature, key)
	}

	if err != nil {
		return fmt.Errorf("%w %w", err, jwt.ErrTokenMalformed)
	}

	// 自定義內容，可能會有複雜的驗證，因此放在最後驗證
	if customValidate != nil {
		if err = customValidate(token.Claims); err != nil {
			return err
		}
	}

	return nil
}

func (p *Parser) parseHeader(headerStr string) (map[string]any, error) {
	bs, err := base64.RawURLEncoding.DecodeString(headerStr)
	if err != nil {
		return nil, err
	}
	var header map[string]any
	if err = json.Unmarshal(bs, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w %w", err, jwt.ErrTokenMalformed)
	}
	if header["typ"] != "JWT" {
		return nil, fmt.Errorf("invalid token type: %s %w", header["typ"], jwt.ErrTokenMalformed)
	}
	algName, ok := header["alg"]
	if !ok {
		return nil, fmt.Errorf("token algorithm not found %w", jwt.ErrTokenMalformed)
	}
	if _, ok = algName.(string); !ok {
		return nil, fmt.Errorf("token algorithm not string %w", jwt.ErrTokenMalformed)
	}
	return header, nil
}

func (p *Parser) parseClaims(claimStr string, out jwt.IClaims) error {
	bs, err := base64.RawURLEncoding.DecodeString(claimStr)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(bs, &out); err != nil {
		return fmt.Errorf("could not base64 decode claim %w. %w", err, jwt.ErrTokenMalformed)
	}
	return nil
}
