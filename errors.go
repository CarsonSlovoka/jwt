package jwt

import "errors"

var (
	ErrSignatureInvalid = errors.New("signature is invalid")
)
