package nhppluginssdk

import (
	"github.com/golang-jwt/jwt/v4"
)

type RefreshTokenJWT struct {
	SessionID string    `json:"session_id"`
	TokenType TokenType `json:"token_type"`
	jwt.RegisteredClaims
}
