package test

import (
	"crypto"
	"crypto/hmac"
	"testing"
)

func Test_hmac(t *testing.T) {
	key := []byte("...private_key...")
	hasher := hmac.New(
		crypto.SHA256.New, // 可以選擇其他不同的方法，例如SHA512
		key,
	)

	// Sign
	var mac1 []byte
	signingString := "my data"
	hasher.Write([]byte(signingString))
	mac1 = hasher.Sum(nil)

	// 清空此hasher的緩存，來重複利用，避免再生成一個hasher物件
	hasher.Reset()

	// Verify
	hasher.Write([]byte(signingString)) // 這是key與內容完全一致的情況下加簽
	mac2 := hasher.Sum(nil)

	// IsValid
	if !hmac.Equal(mac1, mac2) { // 因為所有內容都相同，所以兩者比較當然也都相同
		t.Fatal()
	}

	// hmac的重點在於，即便傳進來驗證的內容相同，但只要key不同，那麼這個認證就還是不會通過
	// 以下我們生成一個key不同的hasher
	hasherAnother := hmac.New(crypto.SHA256.New, []byte("other key"))
	hasherAnother.Write([]byte(signingString)) // 加簽一次原本的內容
	mac3 := hasherAnother.Sum(nil)
	if hmac.Equal(mac3, mac2) { // 因為mac3的key與mac2或者mac1的key不同，所以即便加簽的內容相同，最後驗證仍然不過
		t.Fatal()
	}
}
