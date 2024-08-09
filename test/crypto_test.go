package test

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

const signingString = "my data"

// hmac是對稱式加密，也就是加簽與驗證都用同一個key
// jwt.alg: "HS___"
// https://github.com/golang-jwt/jwt/blob/62e504c2810b67f6b97313424411cfffb25e41b0/hmac.go#L58-L104
func Test_cryptoHmac(t *testing.T) {
	key := []byte("...private_key...")
	hasher := hmac.New(
		crypto.SHA256.New, // 可以選擇其他不同的方法, 例如SHA512，但記得要import _ "crypto/sha512"
		key,
	)

	// Sign
	var mac1 []byte
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

// rsa是非對稱式加密，加密用私鑰, 驗證用公鑰
// JWT: "RS___"
// https://github.com/golang-jwt/jwt/blob/62e504c2810b67f6b97313424411cfffb25e41b0/rsa.go#L49-L93
func Test_cryptoRSA(t *testing.T) {
	// 生成密鑰
	var (
		// rsaKey 在實務上你可以生成此key，然後將其資料保存成檔案
		rsaKey *rsa.PrivateKey // 包含鑰在內
		err    error
	)
	rsaKey, err = rsa.GenerateKey(rand.Reader,
		2048, // 目前有2048, 3072, 4096可以選擇: https://github.com/golang/go/blob/e705a2d16e4ece77e08e80c168382cdb02890f5b/src/crypto/rsa/rsa.go#L301
	)
	if err != nil {
		t.Fatal(err)
	}

	if true { // 這是一個可選項，一般而言我們會把rsa.Key保存下來，私鑰可以寫在環境變數、公鑰可以變成文件曝露出去讓人得知
		pemBlockHeader := make(map[string]string) // 可選項, 如果要給{公、私}鑰都要給
		privateBuf := bytes.NewBuffer(nil)
		_ = pem.Encode(privateBuf, &pem.Block{
			Type:    "RSA PRIVATE KEY",
			Headers: pemBlockHeader,
			Bytes:   x509.MarshalPKCS1PrivateKey(rsaKey),
		})

		publicBuf := bytes.NewBuffer(nil)
		_ = pem.Encode(publicBuf, &pem.Block{
			Type:    "RSA PUBLIC KEY",
			Headers: pemBlockHeader,
			Bytes:   x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey),
		})
		blockPrivate, _ := pem.Decode(privateBuf.Bytes())
		blockPublic, _ := pem.Decode(publicBuf.Bytes())
		_ /*rsaPublicKey*/, _ = x509.ParsePKCS1PublicKey(blockPublic.Bytes)
		rsaKey, _ = x509.ParsePKCS1PrivateKey(blockPrivate.Bytes)
	}

	// Sign
	var signedBytes []byte // 這個是透過私鑰加簽出去的內容
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write([]byte(signingString))
	signedBytes, err = rsa.SignPKCS1v15(rand.Reader, rsaKey, hash, hasher.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}

	// Verify
	var rsaPublicKey *rsa.PublicKey
	rsaPublicKey = &rsaKey.PublicKey // 這邊的正常流程應該是要去讀取公鑰的文件，然後轉換成公鑰，也就是: x509.ParsePKCS1PublicKey(blockPublic.Bytes)
	hasher = hash.New()
	hasher.Write([]byte(signingString))
	if err = rsa.VerifyPKCS1v15(rsaPublicKey, hash, hasher.Sum(nil), // 計算出來的雜湊值+公鑰+之前的簽名，可以知道是否同源
		signedBytes, // 私鑰加簽內容(之前的簽名)
	); err != nil {
		t.Fatal(err)
	}
}
