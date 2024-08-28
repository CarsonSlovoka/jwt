package jwt

import "errors"

var (
	ErrInvalidKeyType        = errors.New("key is of invalid type")
	ErrSignatureInvalid      = errors.New("signature is invalid")
	ErrHashUnavailable       = errors.New("the requested hash function is unavailable")
	ErrTokenMalformed        = errors.New("token is malformed")
	ErrTokenKeyFuncUnknown   = errors.New("token key func unknown")
	ErrTokenSignatureInvalid = errors.New("token signature is invalid")

	ErrTokenRequiredClaimMissing = errors.New("token is missing required claim")
	ErrClaimRequired             = errors.New("claim is required")

	ErrTokenInvalidAudience  = errors.New("token has invalid audience")
	ErrTokenExpired          = errors.New("token is expired")
	ErrTokenUsedBeforeIssued = errors.New("token used before issued")
	ErrTokenInvalidIssuer    = errors.New("token has invalid issuer")
	ErrTokenInvalidSubject   = errors.New("token has invalid subject")
	ErrTokenNotValidYet      = errors.New("token is not valid yet")
	ErrTokenInvalidId        = errors.New("token has invalid id")
	ErrTokenInvalidClaims    = errors.New("token has invalid claims")
	ErrInvalidType           = errors.New("invalid type for claim")
)
