package jwt

import (
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"fmt"
)

func signByHMAC(hash crypto.Hash, signingBytes []byte, privateKey []byte) []byte {
	hasher := hmac.New(hash.New, privateKey)
	hasher.Write(signingBytes)
	return hasher.Sum(nil)
}

func GenerateTokenFromHMAC(claims map[string]any, privateKey []byte) ([]byte, error) {
	header := map[string]any{
		"typ": "JWT",
		"alg": "HS256",
	}
	singingBytes, err := GenSignBytes(header, claims)
	fmt.Printf("加簽的內容:%s\n", string(singingBytes))
	if err != nil {
		return nil, err
	}
	signature := signByHMAC(crypto.SHA256, singingBytes, privateKey)
	// return bytes.Join([][]byte{singingBytes, signature}, []byte{'.'}), nil // signature沒做base64.RawURLEncoding
	return base64.RawURLEncoding.AppendEncode(append(singingBytes, '.'), signature), nil
}

func VerifyHMAC(
	hash crypto.Hash,
	signingBytes []byte, // 本次內容
	signedBytes []byte, // 之前透過Server加簽過的內容, 在jwt下可以透過signingBytes來取得到此內容，理論上要和之前server加簽的原始內容相同
	privateKey []byte,
) error {
	hasher := hmac.New(hash.New, privateKey)
	// fmt.Printf("驗證的內容:%s\n", string(signingBytes))
	hasher.Write(signingBytes)

	signature, err := decodeSegment(signedBytes) // 通常特徵也會用URLEncoding，所以也要還原回去，才是之前算出來的特徵(之前加簽出來的內容)
	if err != nil {
		return err
	}

	if hmac.Equal(hasher.Sum(nil), signature) { // 現有資料算出來的內容，應該要與之前server加簽出來的內容相同
		return nil
	}
	return ErrSignatureInvalid
}
