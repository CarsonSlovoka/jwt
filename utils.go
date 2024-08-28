package jwt

import "encoding/base64"

func decodeSegment(seg []byte) ([]byte, error) {
	// base64.RawURLEncoding.DecodeString(seg)
	enc := base64.RawURLEncoding
	signature := make([]byte, enc.DecodedLen(len(seg)))
	n, err := enc.Decode(signature, seg)
	if err != nil {
		return nil, err
	}
	return signature[:n], nil
}

func encodeSegment(seg []byte) []byte {
	// base64.RawURLEncoding.EncodeToString(seg)
	enc := base64.RawURLEncoding
	buf := make([]byte, enc.EncodedLen(len(seg)))
	enc.Encode(buf, seg)
	return buf
}
