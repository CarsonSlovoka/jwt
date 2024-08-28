package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha512"
	"fmt"
)

type SigningMethodRSA struct {
	Name string
	Hash crypto.Hash // 假設你用crypto.SHA512，那麼import必須要包含"crypto/sha512"，否則會報錯
}

var (
	SigningMethodRSA256 *SigningMethodRSA
	SigningMethodRSA384 *SigningMethodRSA
	SigningMethodRSA512 *SigningMethodRSA
)

func init() {
	SigningMethodRSA256 = &SigningMethodRSA{"RS256", crypto.SHA256}
	SigningMethodRSA384 = &SigningMethodRSA{"RS384", crypto.SHA384}
	SigningMethodRSA512 = &SigningMethodRSA{"RS512", crypto.SHA512}
}

func (m *SigningMethodRSA) AlgName() string {
	return m.Name
}

func (m *SigningMethodRSA) Sign(signingBytes []byte, key any) ([]byte, error) {
	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("RSA sign expects *rsa.PrivateKey. %w", ErrInvalidKeyType)
	}

	if !m.Hash.Available() {
		return nil, ErrHashUnavailable
	}

	hasher := m.Hash.New()
	hasher.Write(signingBytes)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, m.Hash, hasher.Sum(nil))
}

func (m *SigningMethodRSA) Verify(
	signingBytes []byte,
	signature []byte,
	key any,
) (err error) {
	publicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("RSA verify expects *rsa.PublicKey. %w", ErrInvalidKeyType)
	}

	// 加簽本次的內容
	hasher := m.Hash.New()
	hasher.Write(signingBytes)

	if err = rsa.VerifyPKCS1v15(
		publicKey,
		m.Hash, hasher.Sum(nil),
		signature, // 計算出來的雜湊值+公鑰+之前的簽名，可以知道是否同源
	); err != nil {
		return fmt.Errorf("%w %w", err, ErrSignatureInvalid)
	}
	return nil
}
