package jwt

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
)

// ErrEd25519Verification 使其可以被兩種錯誤類型判別
var ErrEd25519Verification = fmt.Errorf("%w %w",
	errors.New("ed25519: verification error"),
	ErrSignatureInvalid,
)

type SigningMethodED25519 struct{}

// AlgName implements the ISigningMethod interface
func (m *SigningMethodED25519) AlgName() string {
	return "EdDSA"
}

// Sign implements the ISigningMethod interface
func (m *SigningMethodED25519) Sign(signingBytes []byte, key any) ([]byte, error) {
	var privateKey crypto.Signer // 這是一個interface
	var ok bool

	// privateKey, ok := key.(ed25519.PrivateKey) // 斷言成指定物件的變化性比較低，改成crypto.Signer會更好
	// return ed25519.Sign(privateKey, signingBytes), nil

	privateKey, ok = key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("ed25519 sign expects crypto.Signer. %w", ErrInvalidKeyType)
	}

	// 用此來確保所提供的Signer，符合ed25519
	if _, ok = privateKey.Public().(ed25519.PublicKey); !ok {
		return nil, ErrInvalidKey
	}

	signature, err := privateKey.Sign(rand.Reader, signingBytes, crypto.Hash(0))
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// Verify implements the ISigningMethod interface
func (m *SigningMethodED25519) Verify(signingBytes []byte, signature []byte, key any) error {
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("ed25519 verify error. expected type: ed25519.PublicKey, got: %T. %w",
			key, ErrInvalidKeyType,
		)
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return ErrInvalidKey
	}

	if !ed25519.Verify(publicKey, signingBytes, signature) {
		return ErrEd25519Verification
	}

	return nil
}
