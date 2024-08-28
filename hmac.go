// HMAC: Keyed-Hash Message Authentication Code
// HMAC 使用對稱式加密，加解與驗證都用同一把鑰匙

package jwt

import (
	"crypto"
	"crypto/hmac"
	"fmt"
)

type SigningMethodHMAC struct {
	Name string
	Hash crypto.Hash // Hash本質是一個uint
}

var (
	SigningMethodHMAC256 *SigningMethodHMAC
	SigningMethodHMAC384 *SigningMethodHMAC
	SigningMethodHMAC512 *SigningMethodHMAC
)

func init() {
	SigningMethodHMAC256 = &SigningMethodHMAC{"HS256", crypto.SHA256}
	SigningMethodHMAC384 = &SigningMethodHMAC{"HS384", crypto.SHA384}
	SigningMethodHMAC512 = &SigningMethodHMAC{"HS512", crypto.SHA512}
}

func (m *SigningMethodHMAC) AlgName() string {
	return m.Name
}

func (m *SigningMethodHMAC) Sign(signingBytes []byte, key any) ([]byte, error) {
	privateKey, ok := key.([]byte)
	if !ok {
		return nil, fmt.Errorf("HMAC verify expects []byte. %w", ErrInvalidKeyType)
	}

	// 由於hash本身是一個uint，所以若你不是從標準庫的變數去給，那麼數值就可能會有問題
	if !m.Hash.Available() {
		return nil, ErrHashUnavailable
	}

	hasher := hmac.New(m.Hash.New, privateKey)
	hasher.Write(signingBytes)
	return hasher.Sum(nil), nil
}

func (m *SigningMethodHMAC) Verify(
	signingBytes []byte, // 本次傳過來的驗證內容: parts[0:2]
	signature []byte, // parts[2]
	key any,
) (err error) {
	privateKey, ok := key.([]byte)
	if !ok {
		return fmt.Errorf("HMAC verify expects []byte. %w", ErrInvalidKeyType)
	}

	// 先取得之前的加簽出來的內容
	signature, err = decodeSegment(signature) // 通常特徵也會用URLEncoding，所以也要還原回去，才是之前算出來的特徵(之前加簽出來的內容)
	if err != nil {
		return err
	}

	// 加簽本次的內容
	hasher := hmac.New(m.Hash.New, privateKey)
	hasher.Write(signingBytes)

	if hmac.Equal(hasher.Sum(nil), signature) { // 現有資料算出來的內容，應該要與之前server加簽出來的內容相同
		return nil
	}
	return ErrSignatureInvalid
}
