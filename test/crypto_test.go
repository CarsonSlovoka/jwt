package test

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"testing"
)

const signingString = "my data"

// hmac是對稱式加密，也就是加簽與驗證都用同一個key
// jwt.alg: "HS___"
// https://github.com/golang-jwt/jwt/blob/62e504c2810b67f6b97313424411cfffb25e41b0/hmac.go#L58-L104
// hmac是一個不可逆的，也就是即便你有私鑰，也無法再從HMAC的值還原回去原本內容
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
	// 內容無法再被還原，但是你可以對內容做驗證，能曉得簽名是否同源
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
			Bytes:   x509.MarshalPKCS1PrivateKey(rsaKey), // PKCS1是一種標準，裡面將資料轉換成適合的長度和格式。例如: 格式: 固定前面多少byte是xxx, 長度: 填充多少垃圾來達到滿長度, 模擬範例: https://go.dev/play/p/W1vH5B7eL5z
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
	if err = rsa.VerifyPKCS1v15(rsaPublicKey, hash, hasher.Sum(nil), // 計算出來的雜湊值公鑰之前的簽名，可以知道是否同源
		signedBytes, // 私鑰加簽內容(之前的簽名)
	); err != nil {
		t.Fatal(err)
	}
}

// 模擬GPG (GNU Privacy Guard)的過程: https://gist.github.com/CarsonSlovoka/1876a3ae7cd821a201d39aa96beccffe
// rsa.OAEP: 提供公鑰給對方，讓對方用此公鑰加密; 得到的內容有辦法再用自己的私鑰解密，來得知對方想給的原始內容
func Test_rsaOAEP(t *testing.T) {
	// 模擬隨機生成對稱式金鑰
	const defaultKeySize = 16 // 由於我們採用AES演算法，他的私鑰長度有限制，對應的長度分別為16, 24, 32對應AES-128, AES-192, or AES-256.
	pairKey := make([]byte, defaultKeySize)
	if _, err := rand.Read(pairKey); err != nil {
		t.Fatal(err)
	}

	// 使用一個對稱式加密演算法來生成會話的密鑰，假設我們使用AES來加密
	var realMessage = []byte("這是一個秘密訊息")
	aesEncryptFunc := func(key, plaintext []byte) ([]byte, error) {
		block, err := aes.NewCipher(key) // key長度有限制必須為16, 24, 32. 對應 AES-128, AES-192, or AES-256
		if err != nil {
			return nil, err
		}
		// 整個密文的長度 = blockSize + len(plaintext)
		ciphertext := make([]byte, aes.BlockSize+len(plaintext))

		// 生成block的內容
		iv := ciphertext[:aes.BlockSize]
		if _, err = io.ReadFull(rand.Reader, iv); err != nil {
			return nil, err
		}

		stream := cipher.NewCFBEncrypter(block, iv)
		stream.XORKeyStream( // 會執行cfb.XORKeyStream, 以plaintext和提供的iv, 計算結果存到ciphertext[aes.BlockSize:]去
			ciphertext[aes.BlockSize:], // 這是輸出。此輸出搭配真實的密鑰，才可以反算回來
			plaintext,
		)
		return ciphertext, nil
	}

	aesDecryptFunc := func(key, ciphertext []byte) ([]byte, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		if len(ciphertext) < aes.BlockSize {
			return nil, fmt.Errorf("ciphertext too short")
		}
		iv := ciphertext[:aes.BlockSize]
		ciphertext = ciphertext[aes.BlockSize:]

		stream := cipher.NewCFBDecrypter(block, iv)
		stream.XORKeyStream(ciphertext, ciphertext)

		return ciphertext, nil
	}
	// 被加密起來的訊息
	encryptMessage, err := aesEncryptFunc(pairKey, realMessage)
	if err != nil {
		t.Fatal(err)
	}

	// 訊息加簽完之後，我們也要對對稱式密鑰以RSA演算法進行加簽
	// 首先我們要先取得接收方給的公鑰，以下我們就直接生成，實際上應該是接收方會以某種形式來提供公鑰，讓發送方曉得
	receiverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("生成密鑰失敗:", err)
		return
	}
	// 接收方的公鑰
	receiverPublicKey := &receiverKey.PublicKey

	// 使用公鑰加密訊息
	label := []byte("") // 填充用標籤 (通常是空的)
	iHash := sha256.New()
	// 用對方的公鑰對會話密鑰加簽
	// 因此即便對方能取得到sessionKeyBytes，但只要對方沒有私鑰，那麼密鑰的內容還是無法得知，也就導致真實的內容無法得知(需要對稱式密鑰)
	sessionKeyBytes, err := rsa.EncryptOAEP(iHash, rand.Reader, receiverPublicKey, pairKey, label)
	if err != nil {
		t.Fatal("Error encrypting message:", err)
		return
	}

	// 以下只是隨便模擬一個簡單的過程，主要是接收方有辦法識別加簽起來的內容與加簽起來的密鑰
	type Header struct {
		MessageSize uint32
		KeySize     uint32
	}
	encryptedMessageBuf := bytes.NewBuffer(nil)
	_ = binary.Write(encryptedMessageBuf, binary.BigEndian, &Header{
		MessageSize: uint32(len(encryptMessage)),
		KeySize:     uint32(len(sessionKeyBytes)),
	})
	encryptedMessageBuf.Write(encryptMessage)
	encryptedMessageBuf.Write(sessionKeyBytes)

	// 以下為接收方會得到的內容
	encryptedMessage := encryptedMessageBuf.Bytes()
	privateKey := receiverKey

	// 以下模擬收方的情形
	// 解析接收的資料內容
	// 這邊只是模擬接收到的資料結構，實際上的資料結構更為複雜
	type ReceiveData struct {
		Header
		Msg []byte
		Key []byte
	}
	var msgSize uint32
	msgSize = binary.BigEndian.Uint32(encryptedMessage) // 這是我們自己訂的結構，其一開始4byte表示訊息長度
	// keySize = binary.BigEndian.Uint32(encryptedMessage[4:]) // 之後的4byte表示, key長度，實際的資料結構更為複雜這只是一種簡化
	var receive ReceiveData
	receive.Msg = encryptedMessage[8 : 8+msgSize] // 8為表頭前8byte(msgSize, keySize)
	receive.Key = encryptedMessage[8+msgSize:]

	// 解出公鑰
	ciphertext := receive.Key
	pairKey2, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, // 此為OAEP的特色，對方已經用己方提供的公鑰加密，用自己的私鑰能解密
		privateKey, // 接收方的私鑰理論上只有自己才會有，因此只要沒有這個私鑰，就沒有辦法把會話密鑰還原
		ciphertext, label,
	)

	// 驗證
	// 驗證密鑰相等
	if err != nil || !bytes.Equal(pairKey, pairKey2) {
		t.Fatal("對稱式密鑰不同", err)
	}

	// 驗證內容一致
	expectedMsg, err := aesDecryptFunc(pairKey2, receive.Msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expectedMsg, realMessage) {
		t.Fatal("解開的內容，應該要與原始一致")
	}
}

// 遺憾的是目前go標準庫，沒有將ed25519或者rsa變成PKCS8的格式，所以出來的內容都會比較短，沒辦法當成Github SSH key用 https://stackoverflow.com/q/71850135/9935654
// 如果要生成ssh key，請考慮使用: "golang.org/x/crypto/ssh"
// https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent
func Test_cryptoEd25519(t *testing.T) {
	// 生成 Ed25519 公鑰和私鑰
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("生成密鑰失敗:", err)
		return
	}

	// 保存至檔案
	var pemBlockHeader map[string]string // 可選項
	privateBuf := pem.EncodeToMemory(&pem.Block{
		Type:    "OPENSSH PRIVATE KEY",
		Headers: pemBlockHeader,
		Bytes:   privateKey,
	})

	publicBuf := pem.EncodeToMemory(&pem.Block{
		Type:    "OPENSSH PUBLIC123 KEY",
		Headers: pemBlockHeader,
		Bytes:   publicKey,
	})
	fmt.Println(string(privateBuf))
	fmt.Println(string(publicBuf))

	// 加簽
	var message = []byte("Hello, ED25519!")
	signature := ed25519.Sign(privateKey, message)

	// 驗證
	if !ed25519.Verify(publicKey, message, signature) {
		t.Fatal("invalid")
	}
}
