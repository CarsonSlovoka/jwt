package jwt

type ISigningMethod interface {
	// AlgName HS256, RS512, ...
	AlgName() string

	// Sign SigningMethodHMAC.Sign, SigningMethodRSA.Sign
	Sign(signingBytes []byte, key any) ([]byte, error)

	// Verify SigningMethodHMAC.Verify, SigningMethodRSA.Verify
	Verify(signingBytes []byte, // parts[0:2]
		signature []byte, // 被Sign()加簽出來的產物 parts[2]
		key any, // 若為非對稱式加密用的是公鑰
	) error
}
