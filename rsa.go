package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

func VerifyRSA(
	hash crypto.Hash,
	signingBytes []byte, // 本次內容
	signedBytes []byte, // 之前加簽過的內容
	publicKey *rsa.PublicKey,
) error {
	hasher := hash.New()
	hasher.Write(signingBytes)
	if rsa.VerifyPKCS1v15(
		publicKey,
		hash, hasher.Sum(nil),
		signedBytes, // 使用公鑰可以驗證此簽名
	) != nil {
		return ErrSignatureInvalid
	}
	return nil
}

func SignByRSA(hash crypto.Hash, signingBytes []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hasher := hash.New()
	hasher.Write(signingBytes)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, hash, hasher.Sum(nil))
}
