package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
)

type Token struct {
	Header map[string]any
	Claims IClaims
	// ISigningMethod // 不鑲嵌它，因為如果使用者直接調用這個方法，會需要處理前置header, claims要被URLEncode之後才能動作
	SigningMethod ISigningMethod
}

func New(signingMethod ISigningMethod) *Token {
	return NewWithClaims(signingMethod, &MapClaims{})
}

func NewWithClaims(signingMethod ISigningMethod, claims IClaims) *Token {
	return &Token{
		Header: map[string]any{
			"typ": "JWT",
			"alg": signingMethod.AlgName(),
		},
		Claims:        claims,
		SigningMethod: signingMethod,
	}
}

// SigningBytes 取得要被加簽的內容
func (t *Token) SigningBytes() ([]byte, error) {
	var h, c []byte
	var err error
	h, err = json.Marshal(t.Header)
	if err != nil {
		return nil, err
	}
	c, err = json.Marshal(t.Claims)
	if err != nil {
		return nil, err
	}
	return bytes.Join([][]byte{encodeSegment(h), encodeSegment(c)}, []byte{'.'}), nil
}

// SignedBytes 取得到完整的jwt字串內容
func (t *Token) SignedBytes(key any) ([]byte, error) {
	signBytes, err := t.SigningBytes()
	if err != nil {
		return nil, err
	}

	signature, err := t.SigningMethod.Sign(signBytes, key)
	if err != nil {
		return nil, err
	}
	return base64.RawURLEncoding.AppendEncode(
		append(signBytes, '.'), // 這部分已經被URLEncode過
		signature,              // 我們將特徵的內容也套用到URLEncode
	), nil
}
