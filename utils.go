package jwt

import "encoding/base64"

func decodeSegment(seg []byte) ([]byte, error) {
	// base64.RawURLEncoding.DecodeString()
	enc := base64.RawURLEncoding
	signature := make([]byte, enc.DecodedLen(len(seg)))
	if _, err := enc.Decode(signature, seg); err != nil {
		return nil, err
	}
	return signature, nil
}
