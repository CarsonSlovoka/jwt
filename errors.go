package jwt

import "errors"

var (
	ErrInvalidKeyType   = errors.New("key is of invalid type")
	ErrSignatureInvalid = errors.New("signature is invalid")
	ErrHashUnavailable  = errors.New("the requested hash function is unavailable")
	ErrInvalidType      = errors.New("invalid type for claim")
)
