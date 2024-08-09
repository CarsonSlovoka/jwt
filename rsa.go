package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha512"
	"encoding/base64"
)

func SignByRSA(
	hash crypto.Hash, // 假設你用crypto.SHA512，那麼import必須要包含"crypto/sha512"，否則會報錯
	signingBytes []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hasher := hash.New()
	hasher.Write(signingBytes)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, hash, hasher.Sum(nil))
}

func GenerateTokenFromRSA(claims map[string]any, privateKey *rsa.PrivateKey) ([]byte, error) {
	header := map[string]any{
		"typ": "JWT",
		"alg": "RS512",
	}
	singingBytes, err := GenSignBytes(header, claims)
	if err != nil {
		return nil, err
	}
	signature, err := SignByRSA(crypto.SHA512, singingBytes, privateKey)
	if err != nil {
		return nil, err
	}
	return base64.RawURLEncoding.AppendEncode(append(singingBytes, '.'), signature), nil
}

func VerifyRSA(
	hash crypto.Hash,
	signingBytes []byte, // 本次內容
	signedBytes []byte, // 之前加簽過的內容
	publicKey *rsa.PublicKey,
) error {
	signature, err := decodeSegment(signedBytes)
	if err != nil {
		return err
	}

	// 計算本次內容的雜湊值
	hasher := hash.New()
	hasher.Write(signingBytes)
	if rsa.VerifyPKCS1v15(
		publicKey,
		hash, hasher.Sum(nil),
		signature, // 計算出來的雜湊值+公鑰+之前的簽名，可以知道是否同源
	) != nil {
		return ErrSignatureInvalid
	}
	return nil
}
