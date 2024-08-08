package jwt

import (
	"crypto"
	"crypto/hmac"
)

func VerifyHMAC(
	hash crypto.Hash,
	signingBytes []byte, // 本次內容
	signedBytes []byte, // 之前透過Server加簽過的內容, 在jwt下可以透過signingBytes來取得到此內容，理論上要和之前server加簽的原始內容相同
	privateKey []byte,
) error {
	hasher := hmac.New(hash.New, privateKey)
	hasher.Write(signingBytes)
	if hmac.Equal(signedBytes, hasher.Sum(nil)) {
		return nil
	}
	return ErrSignatureInvalid
}

func SignByHMAC(hash crypto.Hash, signingBytes []byte, privateKey []byte) []byte {
	hasher := hmac.New(hash.New, privateKey)
	hasher.Write(signingBytes)
	return hasher.Sum(nil)
}
