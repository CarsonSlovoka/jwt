package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

var ErrECDSAVerification = fmt.Errorf("%w %w",
	errors.New("ecdsa: verification error"),
	ErrSignatureInvalid,
)

type SigningMethodECDSA struct {
	Name       string
	Hash       crypto.Hash
	KeyBitSize int
}

var (
	SigningMethodECDSA256 *SigningMethodECDSA
	SigningMethodECDSA384 *SigningMethodECDSA
	SigningMethodECDSA512 *SigningMethodECDSA
)

func init() {
	// "ES256": https://datatracker.ietf.org/doc/html/rfc7519#section-8
	SigningMethodECDSA256 = &SigningMethodECDSA{"ES256", crypto.SHA256, 256} // 橢圓曲線ES256其實就是用了256bit, 其中它的keySize用位元組表示 256/8 = 32
	SigningMethodECDSA384 = &SigningMethodECDSA{"ES384", crypto.SHA384, 384}

	// 用的是 elliptic.P521() 它是一個type Curve interface, 共需要 521/8 = 65.125 byte => 因此實際上需要用66byte才能包含
	SigningMethodECDSA512 = &SigningMethodECDSA{"ES512", crypto.SHA512, 521}
}

// AlgName implements the ISigningMethod interface
func (m *SigningMethodECDSA) AlgName() string {
	return m.Name
}

// Sign implements the ISigningMethod interface
func (m *SigningMethodECDSA) Sign(signingBytes []byte, ecdsaPrivateKey any) ([]byte, error) {
	privateKey, ok := ecdsaPrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ECDSA sign expects *ecdsa.PrivateKey. %w", ErrInvalidKeyType)
	}

	if !m.Hash.Available() {
		return nil, ErrHashUnavailable
	}

	hasher := m.Hash.New()
	hasher.Write(signingBytes)

	var r, s *big.Int
	var err error
	r, s, err = ecdsa.Sign(rand.Reader, privateKey, hasher.Sum(nil))
	if err != nil {
		return nil, err
	}
	// 由於ecdsa驗證的時後，需要r, s的資訊，所以我們必須將這些資訊寫入
	// var signature []byte
	// 以下這樣還會需要寫入長度，取的時候才知道怎麼取
	// signature = append(signature, r.Bytes()...)
	// signature = append(signature, s.Bytes()...)

	// 為了能簡化寫入長度
	// 我們計算一個適當的長度，並且平均分配給r, s

	nCurveBit := privateKey.Curve.Params().BitSize

	if m.KeyBitSize != nCurveBit {
		return nil, ErrInvalidKey
	}

	keyBytes := (nCurveBit + 7) >> 3 // 即若bit/8(換成byte), 如果除不盡就會加1，也就是要多一個byte

	signature := make([]byte, keyBytes<<1) // *2 // 前面KeyBytes放r，剩下的全部給s
	r.FillBytes(signature[0:keyBytes])     // FillBytes用BigEndian的方式把r這個很大的[]uint填充到指定的[]byte之間，它會填滿，如果不夠填會panic，如果buf的尺寸比較大是可以的(但規定多餘的部分必須是0)
	s.FillBytes(signature[keyBytes:])

	return signature, nil
}

// Verify implements the ISigningMethod interface
func (m *SigningMethodECDSA) Verify(signingBytes []byte, signature []byte, key any) error {
	publicKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("ECDSA verify expects *ecdsa.PublicKey. %w", ErrInvalidKeyType)
	}

	// 因為我們在Sign的時候，把簽名出來的r, s放到make([]byte, 2*keyBytes)之中
	// 所以檢驗長度必須要符合
	keyBytes := (m.KeyBitSize + 7) >> 3
	if len(signature) != (keyBytes << 1) { // 2 * keyBytes
		return ErrECDSAVerification
	}

	r := big.NewInt(0).SetBytes(signature[:keyBytes])
	s := big.NewInt(0).SetBytes(signature[keyBytes:])

	if !m.Hash.Available() {
		return ErrHashUnavailable
	}

	hasher := m.Hash.New()
	hasher.Write(signingBytes)

	if ecdsa.Verify(publicKey, hasher.Sum(nil), r, s) {
		return nil
	} else {
		return ErrECDSAVerification
	}
}
