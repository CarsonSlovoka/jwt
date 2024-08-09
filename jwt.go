package jwt

import (
	"encoding/base64"
	"encoding/json"
)

// GenSignBytes 生成出jwt字串的內容
func GenSignBytes(header, claims map[string]any) ([]byte, error) {
	h, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	var buf []byte
	buf = base64.RawURLEncoding.AppendEncode(buf, h)
	buf = append(buf, '.')
	buf = base64.RawURLEncoding.AppendEncode(buf, c)
	// return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c), nil
	return buf, nil
}
